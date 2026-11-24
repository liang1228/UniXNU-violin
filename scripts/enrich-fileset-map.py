#!/usr/bin/env python3
"""Enrich an MH_FILESET pairing map across clang-21 vs Apple-clang LTO deltas.

Never modifies UniXNU upstream files. Starts from the base map emitted by
kits/XnuPrelink/emit_prelink.py (built against the Linux clang-21 + ld64.lld-21
LTO RELEASE reference kernel), and applies four auditable, diversity-checked
passes to close remaining clang-21 vs Apple-clang length/layout gaps:
  1. Unique PAC diversity match (global or class/gap-scoped)
  2. Unique ref-string & call-graph transfer (e.g. SecureDT*, throttle_info)
  3. VTable-anchored OSMetaClass C2/C1 constructor + D2 destructor transfer
  4. Strictly monotone 1-to-1 and small-gap LCS ordered transfer
"""
import argparse
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys


def load_side_info(image_path, entry_name=None):
    from kc_image import Image
    from fileset_match import Side

    raw = Path(image_path).read_bytes()
    top = Image(raw)
    if entry_name is not None:
        _, at = top.entries[entry_name]
        entry = Image(raw, at)
        return top, Side(entry, top.fixups(), entry.mapped())
    return top, Side(top, top.fixups(), top.mapped())


def unique_clean_native_symbol(ref_side, nat_side, ref_addr):
    names = [
        name
        for name in ref_side.symbol_names.get(ref_addr, ())
        if ref_side.named_functions.get(name) == ref_addr
        and not any(part in name for part in ('.cold.', 'OUTLINED_FUNCTION', '.llvm.'))
    ]
    targets = {
        nat_side.named_functions[name]: name
        for name in names
        if name in nat_side.named_functions
    }
    if len(targets) != 1:
        return None, None
    nat_addr, sym = next(iter(targets.items()))
    return nat_addr, sym


def diversity_compatible(orig_side, nat_side, orig_addr, nat_addr):
    for div, orig_set in orig_side.diversity.items():
        if orig_addr in orig_set:
            nat_set = nat_side.diversity.get(div)
            if nat_set and nat_addr not in nat_set:
                return False
    return True


def class_prefix(sym):
    if not sym:
        return None
    m = re.match(r'^__ZN(?:K)?(\d+[A-Za-z_][A-Za-z0-9_]*)', sym)
    return m.group(1) if m else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unixnu', required=True, type=Path)
    parser.add_argument('--prelinked', required=True, type=Path)
    parser.add_argument('--reference', required=True, type=Path)
    parser.add_argument('--native', required=True, type=Path)
    parser.add_argument('--in-map', required=True, type=Path)
    parser.add_argument('--out-map', required=True, type=Path)
    parser.add_argument('--audit-out', type=Path)
    args = parser.parse_args()

    sys.path.insert(0, str(args.unixnu / 'kits/XnuPrelink'))
    top, orig = load_side_info(args.prelinked, 'com.apple.kernel')
    _, ref = load_side_info(args.reference)
    _, nat = load_side_info(args.native)

    base = json.loads(args.in_map.read_text())
    orig_to_nat = {int(k, 16): int(v['native'], 16) for k, v in base['functions'].items()}
    used_nat = set(orig_to_nat.values())
    orig_data_names = {int(k, 16): v.get('name') for k, v in base.get('data', {}).items()}

    orig_to_ref = {}
    used_ref = set()
    for o, n in orig_to_nat.items():
        r_cands = {ref.named_functions[sym] for sym in nat.symbol_names.get(n, ()) if sym in ref.named_functions}
        if len(r_cands) == 1:
            r = next(iter(r_cands))
            orig_to_ref[o] = r
            used_ref.add(r)

    kernel_ranges = orig.mapped
    in_kern = lambda a: any(b <= a < e for b, e in kernel_ranges)
    orig_fixups = top.fixups()
    nat_fixups = nat.image.fixups()
    kext_targets = {
        fix[0]
        for site, fix in orig_fixups.items()
        if in_kern(fix[0]) and not in_kern(site) and orig.in_exec(fix[0])
    }

    # Precompute full PAC diversity tuples (key, div, addrDiv) -> target sets,
    # and map each target function to any matched __ZTV<Class> vtable whose slots point to it.
    orig_divs = defaultdict(set)
    orig_vtable_classes = defaultdict(set)
    vtable_ranges = []
    for va, dname in orig_data_names.items():
        if dname and dname.startswith('__ZTV'):
            vtable_ranges.append((va, dname[5:]))
    vtable_ranges.sort()
    vtable_starts = [va for va, _ in vtable_ranges]
    for site, (tgt, auth, key, div, adiv) in orig_fixups.items():
        if auth and div and orig.in_exec(tgt):
            orig_divs[tgt].add((key, div, adiv))
            if vtable_starts:
                vi = bisect_right(vtable_starts, site) - 1
                if vi >= 0 and 0 <= site - vtable_starts[vi] < 0x1000:
                    orig_vtable_classes[tgt].add(vtable_ranges[vi][1])
    nat_div_to_targets = defaultdict(set)
    for _, (tgt, auth, key, div, adiv) in nat_fixups.items():
        if auth and div and nat.in_exec(tgt):
            nat_div_to_targets[(key, div, adiv)].add(tgt)

    # Precompute unique string owners on orig and ref.
    ref_string_owners = defaultdict(set)
    for r, fn in ref.functions.items():
        for s in set(fn['strings'].values()):
            ref_string_owners[s].add(r)

    added_records = []

    def try_bind(o, r, reason, agree=0, miss=0, left_name=None, right_name=None, nat_override=None):
        if o in orig_to_nat:
            return False
        if r is not None and r in used_ref:
            return False
        if nat_override is not None:
            nat_addr, sym = nat_override
        else:
            nat_addr, sym = unique_clean_native_symbol(ref, nat, r)
        if nat_addr is None or nat_addr in used_nat:
            return False
        if not diversity_compatible(orig, nat, o, nat_addr):
            return False
        orig_to_nat[o] = nat_addr
        used_nat.add(nat_addr)
        if r is not None:
            orig_to_ref[o] = r
            used_ref.add(r)
        elif sym in ref.named_functions and ref.named_functions[sym] not in used_ref:
            rr = ref.named_functions[sym]
            orig_to_ref[o] = rr
            used_ref.add(rr)
            r = rr
        base['functions'][f'{o:#x}'] = {
            'native': f'{nat_addr:#x}',
            'name': sym,
            'addend': 0,
            'how': f'violin-{reason}',
        }
        added_records.append({
            'original': f'{o:#x}',
            'native': f'{nat_addr:#x}',
            'symbol': sym,
            'reason': reason,
            'orig_len': orig.functions[o]['length'],
            'ref_len': ref.functions[r]['length'] if r in ref.functions else 0,
            'agree': agree,
            'miss': miss,
            'kext_target': o in kext_targets,
            'left_anchor': left_name,
            'right_anchor': right_name,
        })
        return True

    def nearest_class_hint(o):
        idx = bisect_left(orig.starts, o)
        classes = Counter()
        for delta in (-3, -2, -1, 1, 2, 3):
            j = idx + delta
            if 0 <= j < len(orig.starts):
                name = base['functions'].get(f'{orig.starts[j]:#x}', {}).get('name')
                cp = class_prefix(name)
                if cp:
                    classes[cp] += 1
        return classes.most_common(1)[0][0] if classes else None

    for round_idx in range(1, 12):
        round_added = 0

        # Pass A: Unique PAC diversity (global, vtable-class-scoped, or neighbor-class-scoped).
        for o in sorted(kext_targets):
            if o in orig_to_nat or o not in orig.functions:
                continue
            divs = orig_divs.get(o)
            if not divs:
                continue
            cands = set()
            for d in divs:
                cands |= {n for n in nat_div_to_targets.get(d, ()) if n not in used_nat and n in nat.functions}
            if not cands:
                continue
            if len(cands) > 1:
                vt_classes = orig_vtable_classes.get(o, set())
                if vt_classes:
                    narrowed = {
                        n for n in cands
                        if any(class_prefix(sym) in vt_classes for sym in nat.symbol_names.get(n, ()))
                    }
                    if len(narrowed) == 1:
                        cands = narrowed
            if len(cands) > 1:
                hint = nearest_class_hint(o)
                if hint:
                    narrowed = {
                        n for n in cands
                        if any(class_prefix(sym) == hint for sym in nat.symbol_names.get(n, ()))
                    }
                    if len(narrowed) == 1:
                        cands = narrowed
            if len(cands) == 1:
                n = next(iter(cands))
                names = [
                    sym for sym in nat.symbol_names.get(n, ())
                    if nat.named_functions.get(sym) == n
                    and not any(p in sym for p in ('.cold.', 'OUTLINED_FUNCTION', '.llvm.'))
                ]
                if len(names) == 1:
                    sym = names[0]
                    r = ref.named_functions.get(sym)
                    if r is None or r not in used_ref:
                        if try_bind(o, r, 'pac-diversity', nat_override=(n, sym)):
                            round_added += 1

        # Pass A2: Single-unmatched-callee transfer on already-matched (orig, ref) pairs.
        for o, r in list(orig_to_ref.items()):
            o_un = [c for c in orig.callees[o] if c not in orig_to_nat and c in orig.functions]
            r_un = [c for c in ref.callees[r] if c not in used_ref and c in ref.functions]
            if len(o_un) == 1 and len(r_un) == 1:
                oc, rc = o_un[0], r_un[0]
                ol, rl = orig.functions[oc]['length'], ref.functions[rc]['length']
                o_strs = set(orig.functions[oc]['strings'].values())
                r_strs = set(ref.functions[rc]['strings'].values())
                if abs(ol - rl) <= max(12, max(ol, rl) * 35 // 100) and (not o_strs or not r_strs or (o_strs & r_strs)):
                    if try_bind(oc, rc, 'single-callee'):
                        round_added += 1

        # Pass B: Unique string match in orig <-> ref (transferred by exact symbol to native).
        for s, o_set in orig.string_owners.items():
            if len(o_set) != 1:
                continue
            o = next(iter(o_set))
            if o in orig_to_nat or o not in orig.functions:
                continue
            r_set = ref_string_owners.get(s)
            if not r_set or len(r_set) != 1:
                continue
            r = next(iter(r_set))
            if r in used_ref:
                continue
            ol, rl = orig.functions[o]['length'], ref.functions[r]['length']
            if abs(ol - rl) <= max(12, max(ol, rl) * 50 // 100):
                if try_bind(o, r, 'ref-string'):
                    round_added += 1

        # Pass C: VTable-anchored OSMetaClass C2 constructor + sibling D2 destructor.
        for o in sorted(kext_targets):
            if o in orig_to_nat or o not in orig.functions:
                continue
            fn = orig.functions[o]
            if fn['calls'] or not (8 <= fn['length'] <= 15):
                continue
            vtables = [orig_data_names.get(a) for _, a in fn['refs'] if (orig_data_names.get(a) or '').startswith('__ZTV')]
            if len(vtables) == 1:
                cls = vtables[0][5:]  # strip __ZTV
                c2_sym = f'__ZN{cls}C2EPK11OSMetaClass'
                c1_sym = f'__ZN{cls}C1EPK11OSMetaClass'
                d2_sym = f'__ZN{cls}D2Ev'
                r_c2 = ref.named_functions.get(c2_sym)
                if r_c2 and r_c2 not in used_ref and try_bind(o, r_c2, 'vtable-c2'):
                    round_added += 1
                    idx = bisect_left(orig.starts, o)
                    if idx + 1 < len(orig.starts):
                        o_c1 = orig.starts[idx + 1]
                        r_c1 = ref.named_functions.get(c1_sym)
                        if r_c1 and o_c1 in orig.functions and not orig.functions[o_c1]['calls'] and 8 <= orig.functions[o_c1]['length'] <= 15:
                            if try_bind(o_c1, r_c1, 'vtable-c1'):
                                round_added += 1
                    if idx + 2 < len(orig.starts):
                        o_d2 = orig.starts[idx + 2]
                        r_d2 = ref.named_functions.get(d2_sym)
                        if r_d2 and o_d2 in orig.functions and not orig.functions[o_d2]['calls'] and orig.functions[o_d2]['length'] <= 6:
                            if try_bind(o_d2, r_d2, 'vtable-d2'):
                                round_added += 1
            # Also match 4-insn D2Ev right before __ZN<cls>dlEPvm (e.g. OSObject::~OSObject()).
            if not fn['calls'] and not fn['refs'] and fn['length'] <= 6:
                idx = bisect_left(orig.starts, o)
                if idx + 1 < len(orig.starts):
                    nxt = base['functions'].get(f'{orig.starts[idx + 1]:#x}', {}).get('name', '')
                    m_dl = re.match(r'^__ZN(\d+[A-Za-z_][A-Za-z0-9_]*)dlEPvm$', nxt)
                    if m_dl:
                        d2_sym = f'__ZN{m_dl.group(1)}D2Ev'
                        r_d2 = ref.named_functions.get(d2_sym)
                        if r_d2 and r_d2 not in used_ref and try_bind(o, r_d2, 'pre-delete-d2'):
                            round_added += 1

        # Pass D: Unique callee + string propagation against ref (catches SecureDTLookupEntry etc.).
        ref_by_callees = defaultdict(list)
        for r, fn in ref.functions.items():
            if r in used_ref:
                continue
            r_strs = frozenset(fn['strings'].values())
            if r_strs:
                for c in ref.callees[r]:
                    ref_by_callees[(c, r_strs)].append(r)
        for o in sorted(kext_targets):
            if o in orig_to_nat or o not in orig.functions:
                continue
            o_strs = frozenset(orig.functions[o]['strings'].values())
            if not o_strs:
                continue
            matched_callees = {orig_to_ref[c] for c in orig.callees[o] if c in orig_to_ref}
            if not matched_callees:
                continue
            cands = set()
            for r, fn in ref.functions.items():
                if r in used_ref:
                    continue
                r_strs = set(fn['strings'].values())
                if not (o_strs <= r_strs):
                    continue
                agree = len(matched_callees & ref.callees[r])
                if agree >= 2 and abs(orig.functions[o]['length'] - fn['length']) <= max(40, max(orig.functions[o]['length'], fn['length']) * 45 // 100):
                    cands.add(r)
            if len(cands) == 1:
                r = next(iter(cands))
                if try_bind(o, r, 'callee-str-prop', agree=len(matched_callees & ref.callees[r])):
                    round_added += 1

        # Pass E: Strictly monotone 1-to-1 and small-gap LCS ordered transfer.
        anchors = sorted(orig_to_ref)
        monotone = [
            anchors[i]
            for i in range(len(anchors))
            if (i == 0 or orig_to_ref[anchors[i - 1]] < orig_to_ref[anchors[i]])
            and (i + 1 == len(anchors) or orig_to_ref[anchors[i]] < orig_to_ref[anchors[i + 1]])
        ]
        for left, right in zip(monotone, monotone[1:]):
            r_left, r_right = orig_to_ref[left], orig_to_ref[right]
            if r_right <= r_left:
                continue
            oa, ob = bisect_right(orig.starts, left), bisect_left(orig.starts, right)
            gap = [o for o in orig.starts[oa:ob] if o not in orig_to_nat and o in orig.functions]
            ra, rb = bisect_right(ref.starts, r_left), bisect_left(ref.starts, r_right)
            fill = [r for r in ref.starts[ra:rb] if r not in used_ref and r in ref.functions]
            if not gap or not fill:
                continue

            left_name = base['functions'].get(f'{left:#x}', {}).get('name')
            right_name = base['functions'].get(f'{right:#x}', {}).get('name')
            proposals = []
            if len(gap) == len(fill) and len(gap) <= 12:
                for o, r in zip(gap, fill):
                    ol, rl = orig.functions[o]['length'], ref.functions[r]['length']
                    if abs(ol - rl) > max(8, max(ol, rl) * 45 // 100):
                        continue
                    o_strs = set(orig.functions[o]['strings'].values())
                    r_strs = set(ref.functions[r]['strings'].values())
                    if o_strs and r_strs and not (o_strs & r_strs):
                        continue
                    agree = sum(1 for t in orig.callees[o] if t in orig_to_ref and orig_to_ref[t] in ref.callees[r])
                    miss = sum(1 for t in orig.callees[o] if t in orig_to_ref and orig_to_ref[t] not in ref.callees[r])
                    if miss > 0 and agree == 0 and len(gap) > 2:
                        continue
                    proposals.append((o, r, '1to1-order', agree, miss))
            elif len(gap) <= 20 and len(fill) <= 20:
                # Callee/string unique hits inside small unequal gaps.
                for o in gap:
                    ol = orig.functions[o]['length']
                    o_strs = set(orig.functions[o]['strings'].values())
                    cands = []
                    for r in fill:
                        rl = ref.functions[r]['length']
                        if abs(ol - rl) > max(8, max(ol, rl) * 45 // 100):
                            continue
                        r_strs = set(ref.functions[r]['strings'].values())
                        if o_strs and r_strs and not (o_strs & r_strs):
                            continue
                        agree = sum(1 for t in orig.callees[o] if t in orig_to_ref and orig_to_ref[t] in ref.callees[r])
                        miss = sum(1 for t in orig.callees[o] if t in orig_to_ref and orig_to_ref[t] not in ref.callees[r])
                        str_hit = bool(o_strs and (o_strs & r_strs))
                        if (str_hit and miss == 0) or (agree >= 2 and miss == 0) or (agree >= 3 and miss * 3 <= agree):
                            cands.append((r, agree, miss, str_hit))
                    if len(cands) == 1:
                        r, agree, miss, str_hit = cands[0]
                        proposals.append((o, r, 'gap-str' if str_hit else 'gap-callees', agree, miss))
                # Also allow unique exact-length (<=2 insns diff) + exact call-count match inside tiny gaps (<=12).
                if not proposals and len(gap) <= 12 and len(fill) <= 12:
                    for oi, o in enumerate(gap):
                        ol = orig.functions[o]['length']
                        oc = len(orig.functions[o]['calls'])
                        o_strs = set(orig.functions[o]['strings'].values())
                        cands = []
                        for ri, r in enumerate(fill):
                            rl = ref.functions[r]['length']
                            rc = len(ref.functions[r]['calls'])
                            r_strs = set(ref.functions[r]['strings'].values())
                            if o_strs != r_strs:
                                continue
                            if abs(ol - rl) <= max(2, max(ol, rl) // 8) and oc == rc:
                                agree = sum(1 for t in orig.callees[o] if t in orig_to_ref and orig_to_ref[t] in ref.callees[r])
                                miss = sum(1 for t in orig.callees[o] if t in orig_to_ref and orig_to_ref[t] not in ref.callees[r])
                                if miss == 0 and (agree > 0 or ol >= 8 or (oi == ri and oi == 0) or (len(gap) - oi == len(fill) - ri and oi == len(gap) - 1)):
                                    cands.append((r, agree, miss))
                        if len(cands) == 1:
                            r, agree, miss = cands[0]
                            proposals.append((o, r, 'gap-exact-len', agree, miss))

            ref_claims = defaultdict(list)
            for p in proposals:
                ref_claims[p[1]].append(p)
            for r, plist in ref_claims.items():
                if len(plist) != 1:
                    continue
                o, r, reason, agree, miss = plist[0]
                if try_bind(o, r, reason, agree=agree, miss=miss, left_name=left_name, right_name=right_name):
                    round_added += 1

        if round_added == 0:
            break

    base['stats']['functions_matched'] = len(base['functions'])
    args.out_map.write_text(json.dumps(base, indent=2) + '\n')
    if args.audit_out:
        args.audit_out.write_text(json.dumps(added_records, indent=2) + '\n')
    kt_added = [r for r in added_records if r['kext_target']]
    print(f'Added {len(added_records)} total functions ({len(kt_added)} kext-facing targets); total matched={len(base["functions"])}')
    for rec in kt_added:
        print(
            f"  {rec['original']} -> {rec['symbol']} ({rec['reason']}, "
            f"len {rec['orig_len']}/{rec['ref_len']}, agree={rec['agree']}/{rec['miss']})"
        )


if __name__ == '__main__':
    main()
