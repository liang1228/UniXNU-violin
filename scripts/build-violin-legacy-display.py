#!/usr/bin/env python3
"""Build 24A446 arm64e libNativeLegacyDisplay.late.a with strict PAC alignment.

Reads upstream source/UniXNU/drivers/GopFramebuffer/NativeLegacyDisplay.cpp
read-only (zero upstream edits), generates OriginalLegacyFramebufferABI.h and
BTI/B original kext stubs from the pinned 24A446 kernelcache + original-classes.json,
rewrites & audits all 379 arm64e PAC vtable slot diversities and virtual call-site
movk immediates, removes __DATA,__mod_init_func for deferred metaclass registration,
and emits libNativeLegacyDisplay.late.a + build-report.json.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys


NAMED_SLOTS = {
    186: ("isMainDisplay", "virtual bool isMainDisplay();"),
    190: ("getDotPitch", "virtual IOReturn getDotPitch(uint32_t *pitch);"),
    216: ("supportedFrameInfo", "virtual IOReturn supportedFrameInfo(uint32_t index, uint32_t *count, char *key, uint32_t *mask) = 0;"),
    261: ("getDisplayDimensions", "virtual void getDisplayDimensions(uint32_t *width, uint32_t *height);"),
    305: ("startHardware", "virtual bool startHardware();"),
    307: ("kickSwapQueue", "virtual void kickSwapQueue();"),
    312: ("completeCurrentSwap", "virtual void completeCurrentSwap();"),
    313: ("validateSwap", "virtual bool validateSwap(const OriginalLegacySwapRequest *request);"),
    319: ("getRefreshAttributes", "virtual bool getRefreshAttributes(uint64_t *words, bool fixed);"),
    358: ("collectCompletionReports", "virtual IOReturn collectCompletionReports(uint32_t swapID, void *reports, uint32_t *count, uint32_t maxCount) = 0;"),
    366: ("cancelSwapsAfterTimeout", "virtual bool cancelSwapsAfterTimeout() = 0;"),
    375: ("applyStateRequest", "virtual IOReturn applyStateRequest(const OriginalLegacyStateRequest *request, bool async);"),
}

BASE_OVERRIDES = {
    14: "void free() override;",
    21: "bool init(OSDictionary *properties = nullptr) override;",
    44: "IOReturn setProperties(OSObject *properties) override;",
    79: "void systemWillShutdown(IOOptionBits specifier) override;",
    85: "IOService *probe(IOService *provider, SInt32 *score) override;",
    86: "bool start(IOService *provider) override;",
    87: "void stop(IOService *provider) override;",
    111: "IOWorkLoop *getWorkLoop() const override;",
    141: "IOReturn newUserClient(task_t owningTask, void *securityID, UInt32 type, IOUserClient **handler) override;",
    155: "IOReturn setPowerState(unsigned long powerStateOrdinal, IOService *whatDevice) override;",
}

EXPECTED_0_167_OVERRIDES = [0, 1, 7, 14, 21, 44, 79, 85, 86, 87, 111, 141, 155]
EXPECTED_PURE_SLOTS = [214, 216, 257, 258, 324, 325, 358, 359, 366]
GUARDED_LEAVES = [214, 257, 258, 324, 325, 359]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def parse_macho_object(data: bytes):
    magic, cpu, cpusub, filetype, ncmds, sizeofcmds, flags, _ = struct.unpack_from("<8I", data, 0)
    if magic != 0xFEEDFACF or cpu != 0x0100000C or filetype != 1:
        raise SystemExit(f"Not an arm64/arm64e MH_OBJECT (magic={magic:#x} cpu={cpu:#x} type={filetype})")
    sections = []
    symbols = []
    pos = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<2I", data, pos)
        if cmd == 0x19:  # LC_SEGMENT_64
            nsects = struct.unpack_from("<I", data, pos + 64)[0]
            spos = pos + 72
            for _ in range(nsects):
                sname = data[spos:spos + 16].split(b"\0", 1)[0].decode()
                segname = data[spos + 16:spos + 32].split(b"\0", 1)[0].decode()
                addr, size, offset, align, reloff, nreloc, sflags = struct.unpack_from("<2Q5I", data, spos + 32)
                sections.append({
                    "name": sname,
                    "seg": segname,
                    "addr": addr,
                    "size": size,
                    "offset": offset,
                    "reloff": reloff,
                    "nreloc": nreloc,
                    "flags": sflags,
                })
                spos += 80
        elif cmd == 0x2:  # LC_SYMTAB
            symoff, nsyms, stroff, strsize = struct.unpack_from("<4I", data, pos + 8)
            for idx in range(nsyms):
                strx, ntype, nsect, ndesc, nval = struct.unpack_from("<IBBHQ", data, symoff + idx * 16)
                end = data.index(b"\0", stroff + strx)
                name = data[stroff + strx:end].decode()
                symbols.append({
                    "index": idx,
                    "name": name,
                    "type": ntype,
                    "sect": nsect,
                    "desc": ndesc,
                    "val": nval,
                })
        pos += cmdsize
    return sections, symbols


def generate_abi_header(cls_info: dict, req_info: dict) -> str:
    size = int(cls_info["size"], 16)
    f = cls_info["field"]
    rf = req_info["field"]
    lines = [
        "// SPDX-License-Identifier: BSD-2-Clause-Patent",
        "// Auto-generated by build-violin-legacy-display.py from pinned 24A446 kernelcache.",
        "#pragma once",
        "#include <IOKit/IOService.h>",
        "#include <IOKit/IOUserClient.h>",
        "#include <string.h>",
        "",
        f"static constexpr unsigned kLegacyCurrentSwap = {f['current_swap']};",
        f"static constexpr unsigned kLegacyPendingHead = {f['pending_head']};",
        f"static constexpr unsigned kLegacyPendingTail = {f['pending_tail']};",
        f"static constexpr unsigned kLegacyVsyncClients = {f['vsync_clients']};",
        f"static constexpr unsigned kLegacyDisplayWidth = {f['display_width']};",
        f"static constexpr unsigned kLegacyDisplayHeight = {f['display_height']};",
        "",
        f"static constexpr unsigned kRequestRect0 = {rf['source_rects']};",
        f"static constexpr unsigned kRequestRect1 = {rf['destination_rects']};",
        f"static constexpr unsigned kRequestId = {rf['request_id']};",
        f"static constexpr unsigned kRequestMasks = {rf['layers_updated']};",
        f"static constexpr unsigned kRequestOptions = {rf['options']};",
        f"static constexpr unsigned kRequestDims = {rf['destination_width']};",
        f"static constexpr unsigned kRequestSurfaces = {rf['surfaces']};",
        f"static constexpr unsigned kRequestQueueNext = {rf['queue_next']};",
        f"static constexpr unsigned kRequestQueuePrevious = {rf['queue_previous']};",
        "",
        "struct OriginalLegacySwapRequest;",
        "",
        "// Layout verified against 24A446 IOMobileFramebufferLegacy slot 375 (0xfffffe000a2931dc):",
        "// +0 skip0 (u32), +4 state0 (u32 -> +0x1c0c), +8 skip1 (u32), +12 powered (u32 -> +0x1c10), +16 force (u8).",
        "struct OriginalLegacyStateRequest {",
        "    uint32_t skipState0;",
        "    uint32_t state0;",
        "    uint32_t skipPowered;",
        "    uint32_t powered;",
        "    uint8_t force;",
        "    uint8_t reserved[15];",
        "};",
        "",
        "#define NATIVE_LEGACY_LEAVES(M) \\",
        "    " + " ".join(f"M({s})" for s in GUARDED_LEAVES),
        "",
        "class IOMobileFramebufferLegacy : public IOService {",
        "    OSDeclareAbstractStructors(IOMobileFramebufferLegacy)",
        f"    unsigned char originalPrivate[{size:#x} - sizeof(IOService)];",
        "",
        "protected:",
        "    void installBootDimensions(uint32_t width, uint32_t height) {",
        "        auto *self = reinterpret_cast<unsigned char *>(this);",
        "        memcpy(self + kLegacyDisplayWidth, &width, sizeof(width));",
        "        memcpy(self + kLegacyDisplayHeight, &height, sizeof(height));",
        "    }",
        "    const OriginalLegacySwapRequest *pendingSwapRequest() const {",
        "        const OriginalLegacySwapRequest *head = nullptr;",
        "        memcpy(&head, reinterpret_cast<const unsigned char *>(this) + kLegacyPendingHead, sizeof(head));",
        "        return head;",
        "    }",
        "    bool activateOnlyPendingSwap(const OriginalLegacySwapRequest *request) {",
        "        auto *self = reinterpret_cast<unsigned char *>(this);",
        "        const OriginalLegacySwapRequest *current = nullptr;",
        "        const OriginalLegacySwapRequest *head = nullptr;",
        "        memcpy(&current, self + kLegacyCurrentSwap, sizeof(current));",
        "        memcpy(&head, self + kLegacyPendingHead, sizeof(head));",
        "        if (!request || current != nullptr || head != request) {",
        "            return false;",
        "        }",
        "        auto *req = const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(request));",
        "        OriginalLegacySwapRequest *next = nullptr;",
        "        OriginalLegacySwapRequest **prev = nullptr;",
        "        memcpy(&next, req + kRequestQueueNext, sizeof(next));",
        "        memcpy(&prev, req + kRequestQueuePrevious, sizeof(prev));",
        "        auto **headSlot = reinterpret_cast<OriginalLegacySwapRequest **>(self + kLegacyPendingHead);",
        "        if (prev != headSlot) {",
        "            return false;",
        "        }",
        "        if (next != nullptr) {",
        "            auto *nextBytes = reinterpret_cast<unsigned char *>(next);",
        "            OriginalLegacySwapRequest **nextPrev = nullptr;",
        "            memcpy(&nextPrev, nextBytes + kRequestQueuePrevious, sizeof(nextPrev));",
        "            if (nextPrev != reinterpret_cast<OriginalLegacySwapRequest **>(req + kRequestQueueNext)) {",
        "                return false;",
        "            }",
        "            memcpy(nextBytes + kRequestQueuePrevious, &prev, sizeof(prev));",
        "        } else {",
        "            memcpy(self + kLegacyPendingTail, &prev, sizeof(prev));",
        "        }",
        "        memcpy(prev, &next, sizeof(next));",
        "        OriginalLegacySwapRequest *zero = nullptr;",
        "        memcpy(req + kRequestQueueNext, &zero, sizeof(zero));",
        "        memcpy(req + kRequestQueuePrevious, &zero, sizeof(zero));",
        "        memcpy(self + kLegacyCurrentSwap, &request, sizeof(request));",
        "        return true;",
        "    }",
        "",
        "public:",
        "    using IOService::setProperty;",
    ]
    for slot in sorted(BASE_OVERRIDES):
        lines.append(f"    {BASE_OVERRIDES[slot]}")
    for slot in range(168, cls_info["slots"]):
        if slot in NAMED_SLOTS:
            lines.append(f"    {NAMED_SLOTS[slot][1]}")
        elif slot in GUARDED_LEAVES:
            lines.append(f"    virtual __attribute__((noreturn)) void opaque{slot}() = 0;")
        else:
            lines.append(f"    virtual void opaque{slot}();")
    lines.extend([
        "};",
        f'static_assert(sizeof(IOMobileFramebufferLegacy) == {size:#x}, "24A446 IOMobileFramebufferLegacy size");',
        "",
    ])
    return "\n".join(lines)


def patch_and_audit_pac(raw_obj: bytes, orig_divs: list[int], expected_slots: int):
    buf = bytearray(raw_obj)
    sections, symbols = parse_macho_object(raw_obj)
    sym_by_name = {s["name"]: s for s in symbols if s["sect"] != 0}
    vt_sym = sym_by_name.get("__ZTV19NativeLegacyDisplay")
    if vt_sym is None:
        raise SystemExit("Missing __ZTV19NativeLegacyDisplay in compiled object")
    vt_sec = sections[vt_sym["sect"] - 1]
    vt_base_addr = vt_sym["val"]
    vt_base_off = vt_base_addr - vt_sec["addr"]

    # Inspect all relocations targeting __ZTV19NativeLegacyDisplay
    slot_relocs = {}
    for i in range(vt_sec["nreloc"]):
        r_addr, r_info = struct.unpack_from("<2I", raw_obj, vt_sec["reloff"] + i * 8)
        r_sym = r_info & 0xFFFFFF
        r_pcrel = (r_info >> 24) & 1
        r_len = (r_info >> 25) & 3
        r_ext = (r_info >> 27) & 1
        r_type = (r_info >> 28) & 0xF
        if vt_base_off + 16 <= r_addr < vt_base_off + 16 + (expected_slots + 2) * 8:
            if (r_addr - (vt_base_off + 16)) % 8 != 0:
                raise SystemExit(f"Unaligned vtable reloc at {r_addr:#x}")
            slot = (r_addr - (vt_base_off + 16)) // 8
            if r_type != 11 or r_ext != 1 or r_len != 3 or r_pcrel != 0:
                raise SystemExit(f"Slot {slot}: expected ARM64_RELOC_AUTHENTICATED_POINTER (type=11), got type={r_type} ext={r_ext} len={r_len}")
            slot_relocs[slot] = (r_addr, symbols[r_sym]["name"])

    if len(slot_relocs) != expected_slots or set(slot_relocs) != set(range(expected_slots)):
        raise SystemExit(f"Expected exact {expected_slots} vtable slots (0..{expected_slots-1}), got {len(slot_relocs)} (max={max(slot_relocs)})")

    synth_divs = {}
    base_mismatches = []
    rewritten_slots = 0
    compiled_slot_syms = []
    for slot in range(expected_slots):
        r_addr, target_name = slot_relocs[slot]
        compiled_slot_syms.append(target_name)
        file_pos = vt_sec["offset"] + r_addr
        word = struct.unpack_from("<Q", buf, file_pos)[0]
        auth = (word >> 63) & 1
        key = (word >> 49) & 3
        addr_div = (word >> 48) & 1
        div = (word >> 32) & 0xFFFF
        addend = word & 0xFFFFFFFF
        if (auth, key, addr_div, addend) != (1, 0, 1, 0):
            raise SystemExit(f"Slot {slot} ({target_name}): unexpected auth pointer encoding word={word:#018x}")
        synth_divs[slot] = div
        if slot < 168:
            if div != orig_divs[slot]:
                base_mismatches.append((slot, target_name, hex(div), hex(orig_divs[slot])))
        else:
            if div != orig_divs[slot]:
                new_word = (word & ~(0xFFFF << 32)) | (orig_divs[slot] << 32)
                struct.pack_into("<Q", buf, file_pos, new_word)
                rewritten_slots += 1

    if base_mismatches:
        raise SystemExit(f"IOService 0..167 PAC diversity mismatch (must be 0): {base_mismatches[:10]}")

    # Audit and rewrite virtual call-site movk immediates across all __TEXT,__text instructions
    text_sec = next(s for s in sections if s["seg"] == "__TEXT" and s["name"] == "__text")
    text_base = text_sec["offset"]
    text_size = text_sec["size"]
    nwords = text_size // 4
    words = list(struct.unpack_from(f"<{nwords}I", buf, text_base))

    # Map code offset -> enclosing symbol name
    text_syms = sorted(
        [(s["val"] - text_sec["addr"], s["name"]) for s in symbols if s["sect"] == sections.index(text_sec) + 1 and s["name"]],
        key=lambda x: x[0],
    )

    def sym_for_off(byte_off: int) -> str:
        cur = "<unknown>"
        for soff, sname in text_syms:
            if soff <= byte_off:
                cur = sname
            else:
                break
        return cur

    # 1) Verify vptr DA PAC diversity == 0xCDA1 in NativeLegacyDisplay constructors
    vptr_pacda_divs = []
    for i, w in enumerate(words):
        # pacda Xd, Xn: 0xDAC10800 mask 0xFFFFFC00
        if (w & 0xFFFFFC00) == 0xDAC10800:
            rn = (w >> 5) & 0x1F
            for j in range(i - 1, max(-1, i - 6), -1):
                pw = words[j]
                # movk Xd, #imm16, lsl #48: 0xF2E00000 mask 0xFFE00000
                if (pw & 0xFFE00000) == 0xF2E00000 and (pw & 0x1F) == rn:
                    imm16 = (pw >> 5) & 0xFFFF
                    vptr_pacda_divs.append((sym_for_off(i * 4), hex(imm16)))
                    break
    if not vptr_pacda_divs or any(int(d, 16) != 0xCDA1 for _, d in vptr_pacda_divs):
        raise SystemExit(f"Unexpected vptr PACDA diversities (expected all 0xCDA1): {vptr_pacda_divs}")

    # Map __TEXT,__text relocation offsets -> symbol name (to detect -fapple-kext __ZTV super-calls!)
    text_reloc_syms = {}
    for i in range(text_sec["nreloc"]):
        r_addr, r_info = struct.unpack_from("<2I", raw_obj, text_sec["reloff"] + i * 8)
        r_sym = r_info & 0xFFFFFF
        r_ext = (r_info >> 27) & 1
        if r_ext:
            text_reloc_syms[r_addr] = symbols[r_sym]["name"]

    # 2) Inspect EVERY blraa / braa in __TEXT,__text
    patched_callsites = []
    audited_base_callsites = 0
    for i, w in enumerate(words):
        is_blraa = (w & 0xFFFFFC00) == 0xD73F0800
        is_braa = (w & 0xFFFFFC00) == 0xD71F0800
        if not (is_blraa or is_braa):
            continue
        rn_target = (w >> 5) & 0x1F
        rm_mod = w & 0x1F

        # Find the movk rm_mod, #div, lsl #48 immediately preceding this call
        movk_idx = None
        movk_div = None
        for j in range(i - 1, max(-1, i - 16), -1):
            pw = words[j]
            if (pw & 0xFFE00000) == 0xF2E00000 and (pw & 0x1F) == rm_mod:
                movk_idx = j
                movk_div = (pw >> 5) & 0xFFFF
                break
        if movk_idx is None:
            raise SystemExit(f"Unrecognized {'blraa' if is_blraa else 'braa'} at {sym_for_off(i*4)}+{i*4:#x}: no movk for x{rm_mod}")

        # Determine vtable byte offset and whether this is a -fapple-kext __ZTV super-call (offset = 16 + slot*8)
        slot_byte_off = None
        add_idx = None
        addr_reg = rm_mod
        for j in range(movk_idx - 1, max(-1, movk_idx - 12), -1):
            pw = words[j]
            if (pw & 0xFFE0FFE0) == 0xAA0003E0 and (pw & 0x1F) == addr_reg:
                addr_reg = (pw >> 16) & 0x1F
                break

        for j in range(movk_idx - 1, max(-1, i - 24), -1):
            pw = words[j]
            # Pre-indexed LDR Xt, [Xn, #simm9]! : 0xF8400C00 mask 0xFFE00C00
            if (pw & 0xFFE00C00) == 0xF8400C00 and ((pw >> 5) & 0x1F) == addr_reg:
                imm9 = (pw >> 12) & 0x1FF
                if imm9 & 0x100:
                    imm9 -= 0x200
                slot_byte_off = imm9
                add_idx = j
                break
            # ADD Xd, Xn, #imm12 (shift=0): 0x91000000 mask 0xFFC00000
            if (pw & 0xFFC00000) == 0x91000000 and (pw & 0x1F) == addr_reg:
                slot_byte_off = (pw >> 10) & 0xFFF
                add_idx = j
                break
            # ADD Xd, Xn, Xm (shifted register, shift=0): 0x8B000000 mask 0xFFE0FC00
            if (pw & 0xFFE0FC00) == 0x8B000000 and (pw & 0x1F) == addr_reg:
                rm_off = (pw >> 16) & 0x1F
                for k in range(j - 1, max(-1, j - 8), -1):
                    kw = words[k]
                    if ((kw & 0x7FE00000) == 0x52800000) and (kw & 0x1F) == rm_off:
                        slot_byte_off = (kw >> 5) & 0xFFFF
                        add_idx = j
                        break
                if slot_byte_off is not None:
                    break
            # Unsigned LDR Xt, [Xn, #imm12*8]
            if (pw & 0xFFC00000) == 0xF9400000 and (pw & 0x1F) == rn_target:
                imm12 = (pw >> 10) & 0xFFF
                if imm12 != 0:
                    slot_byte_off = imm12 * 8
                    add_idx = j
                    break

        if slot_byte_off is None or slot_byte_off < 0 or slot_byte_off % 8 != 0:
            raise SystemExit(
                f"Cannot determine vtable slot offset for {'blraa' if is_blraa else 'braa'} "
                f"at {sym_for_off(i*4)}+{i*4:#x} (div={movk_div:#06x}, byte_off={slot_byte_off})"
            )

        # Check if preceded within 6 instructions by a __ZTV* GOT relocation (meaning -fapple-kext super-call: +16 vtable header)
        ztv_super = None
        for k in range(add_idx - 1, max(-1, add_idx - 6), -1):
            rsym = text_reloc_syms.get(k * 4)
            if rsym and rsym.startswith("__ZTV"):
                ztv_super = rsym
                break

        if ztv_super is not None:
            if slot_byte_off < 16:
                raise SystemExit(f"Super-call via {ztv_super} has byte_off={slot_byte_off} < 16 at {sym_for_off(i*4)}+{i*4:#x}")
            slot = (slot_byte_off - 16) // 8
            if ztv_super == "__ZTV25IOMobileFramebufferLegacy" and slot >= 168:
                if slot >= expected_slots:
                    raise SystemExit(f"Out-of-range super slot {slot} at {sym_for_off(i*4)}+{i*4:#x}")
                if movk_div != synth_divs[slot]:
                    raise SystemExit(
                        f"Super-call slot {slot} at {sym_for_off(i*4)}+{i*4:#x} has div={movk_div:#06x}, "
                        f"expected clang synth div={synth_divs[slot]:#06x}"
                    )
                new_div = orig_divs[slot]
                if new_div != movk_div:
                    old_ins = words[movk_idx]
                    new_ins = (old_ins & ~(0xFFFF << 5)) | (new_div << 5)
                    words[movk_idx] = new_ins
                    struct.pack_into("<I", buf, text_base + movk_idx * 4, new_ins)
                patched_callsites.append({
                    "func": sym_for_off(i * 4),
                    "offset": hex(i * 4),
                    "op": ("super-" + ("blraa" if is_blraa else "braa")),
                    "slot": slot,
                    "method": NAMED_SLOTS.get(slot, (f"opaque{slot}", ""))[0],
                    "old_div": hex(movk_div),
                    "new_div": hex(new_div),
                })
            else:
                if ztv_super == "__ZTV25IOMobileFramebufferLegacy" and movk_div != orig_divs[slot]:
                    raise SystemExit(
                        f"Base super-call slot {slot} via {ztv_super} at {sym_for_off(i*4)}+{i*4:#x} "
                        f"has div={movk_div:#06x} != orig={orig_divs[slot]:#06x}"
                    )
                audited_base_callsites += 1
            continue

        slot = slot_byte_off // 8
        if slot >= 168:
            if slot >= expected_slots:
                raise SystemExit(f"Out-of-range vtable slot {slot} at {sym_for_off(i*4)}+{i*4:#x}")
            if movk_div != synth_divs[slot]:
                raise SystemExit(
                    f"Callsite slot {slot} at {sym_for_off(i*4)}+{i*4:#x} has div={movk_div:#06x}, "
                    f"expected clang synth div={synth_divs[slot]:#06x}"
                )
            new_div = orig_divs[slot]
            if new_div != movk_div:
                old_ins = words[movk_idx]
                new_ins = (old_ins & ~(0xFFFF << 5)) | (new_div << 5)
                words[movk_idx] = new_ins
                struct.pack_into("<I", buf, text_base + movk_idx * 4, new_ins)
            patched_callsites.append({
                "func": sym_for_off(i * 4),
                "offset": hex(i * 4),
                "op": "blraa" if is_blraa else "braa",
                "slot": slot,
                "method": NAMED_SLOTS.get(slot, (f"opaque{slot}", ""))[0],
                "old_div": hex(movk_div),
                "new_div": hex(new_div),
            })
        else:
            audited_base_callsites += 1

    return bytes(buf), compiled_slot_syms, {
        "vptr_pacda_checks": len(vptr_pacda_divs),
        "vtable_slots_total": expected_slots,
        "vtable_base_0_167_mismatches": 0,
        "vtable_subclass_168_378_rewritten": rewritten_slots,
        "callsites_base_lt_168_audited": audited_base_callsites,
        "callsites_subclass_ge_168_patched": patched_callsites,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tree", type=Path, default=Path("/opt/unixnu-out/violin/ipados-27.0.1-24A446/violin/tree"))
    ap.add_argument("--unixnu", type=Path, default=Path("/mnt/e/workspace/projects/unixnu-violin/source/UniXNU"))
    ap.add_argument("--kernelcache", type=Path, default=Path("/opt/unixnu-out/ipsw/24A446/kernelcache.decompressed"))
    ap.add_argument("--out-dir", type=Path, default=Path("/opt/unixnu-out/stage7-legacy-display/native-legacy-display"))
    ap.add_argument("--probe", type=Path, default=Path("/mnt/e/workspace/projects/unixnu-violin/source/UniXNU-violin/drivers/ViolinGopProbe/ViolinLegacyDisplayProbe.cpp"))
    ap.add_argument("--collection-slide", type=lambda s: int(s, 0), default=0x1F000000000)
    args = ap.parse_args()

    tree = args.tree.resolve()
    unixnu = args.unixnu.resolve()
    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)

    sys.path.insert(0, str(unixnu / "kits/XnuPrelink"))
    sys.path.insert(0, str(unixnu / "scripts"))
    from kc_image import Image as KCImage
    from kernel_target import ARCH, TRIPLE, check_object

    if ARCH != "arm64e":
        raise SystemExit(f"Expected UNIXNU_XNU_ARCH=arm64e, got {ARCH!r}")

    abi_path = unixnu / "profiles/os/ipados-27.0.1-24A446/abi/original-classes.json"
    abi = json.loads(abi_path.read_text())
    kc_bytes = args.kernelcache.read_bytes()
    kc_sha = sha256_bytes(kc_bytes)
    if kc_sha != abi["kernelcache_sha256"]:
        raise SystemExit(f"kernelcache SHA-256 mismatch: {kc_sha} != {abi['kernelcache_sha256']}")

    kc = KCImage(kc_bytes)
    fixups = kc.fixups()
    cls = abi["classes"]["IOMobileFramebufferLegacy"]
    req = abi["classes"]["IOMFBSwapIORequest"]
    surf = abi["classes"]["IOSurface"]

    vtable_va = int(cls["vtable"], 16)
    vptr_va = vtable_va + 16
    slots = cls["slots"]
    pure_va = int(cls["pure_virtual"], 16)

    orig_vas = []
    orig_divs = []
    pure_slots = []
    for s in range(slots):
        t, auth, key, div, ad = fixups[vptr_va + s * 8]
        if (auth, key, ad) != (1, 0, 1):
            raise SystemExit(f"Original slot {s} has unexpected auth tuple {(auth, key, ad)}")
        orig_vas.append(t)
        orig_divs.append(div)
        if t == pure_va:
            pure_slots.append(s)
    if pure_slots != EXPECTED_PURE_SLOTS:
        raise SystemExit(f"Pure slots changed: {pure_slots} != {EXPECTED_PURE_SLOTS}")
    for name, s in cls["slot"].items():
        if s not in NAMED_SLOTS or NAMED_SLOTS[s][0] != name:
            raise SystemExit(f"ABI JSON slot mismatch: {name}={s}")

    # 1) Generate OriginalLegacyFramebufferABI.h
    abi_header_path = out / "OriginalLegacyFramebufferABI.h"
    abi_header_path.write_text(generate_abi_header(cls, req))

    # 2) Compile upstream NativeLegacyDisplay.cpp read-only
    recipe_path = tree / "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json"
    record = json.loads(recipe_path.read_text().strip().rstrip(","))
    source = unixnu / "drivers/GopFramebuffer/NativeLegacyDisplay.cpp"
    raw_obj = out / "NativeLegacyDisplay.raw.o"

    cmd = []
    args_list = record["arguments"]
    i = 0
    while i < len(args_list):
        v = args_list[i]
        if v == record["file"]:
            cmd.append(str(source))
        elif v == "-o":
            cmd.extend(["-o", str(raw_obj)])
            i += 1
        elif v in ("-MF", "-MT", "-MQ", "-MJ"):
            i += 1
        elif v in ("-MD", "-MMD", "-MP"):
            pass
        elif v == "-Xclang" and i + 1 < len(args_list) and args_list[i + 1].startswith("-W"):
            i += 1
        elif not v.startswith("-W"):
            cmd.append(v)
        i += 1

    cmd.extend([
        "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-parameter", "-Wno-c99-designator", "-Wno-reorder-init-list",
        "-Wno-deprecated-enum-enum-conversion", "-Wno-unnecessary-virtual-specifier",
        "-Wno-missing-designated-field-initializers", "-Wno-unused-but-set-global",
        "-DNATIVE_LEGACY_CANCEL_SWAPS=1",
        "-I", str(out),
        "-I", str(tree / ".cache/xnu-work/osfmk"),
    ])
    (out / "compile-command.json").write_text(json.dumps(cmd, indent=2) + "\n")
    res = subprocess.run(cmd, cwd=record["directory"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    (out / "compile.log").write_text(res.stdout)
    if res.returncode != 0:
        raise SystemExit(f"NativeLegacyDisplay.cpp compile failed:\n{res.stdout[-4000:]}")
    check_object(raw_obj.read_bytes(), "NativeLegacyDisplay.raw.o")

    # 3) Strict arm64e PAC diversity rewrite + call-site audit
    pac_bytes, compiled_slot_syms, pac_audit = patch_and_audit_pac(raw_obj.read_bytes(), orig_divs, slots)
    pac_obj = out / "NativeLegacyDisplay.pac.o"
    pac_obj.write_bytes(pac_bytes)
    check_object(pac_bytes, "NativeLegacyDisplay.pac.o")

    # 4) Resolve all original bindings required by NativeLegacyDisplay.pac.o
    _, pac_syms = parse_macho_object(pac_bytes)
    undefined = {s["name"] for s in pac_syms if s["type"] == 1}

    code_bindings = {
        "__ZN25IOMobileFramebufferLegacyC2EPK11OSMetaClass": int(cls["constructor"], 16),
        "__ZN25IOMobileFramebufferLegacyD2Ev": int(cls["destructor"], 16),
        "_native_legacy_vsync_notify": int(cls["function"]["vsync_notify"], 16),
        "_native_legacy_set_refresh_properties": int(cls["function"]["set_refresh_properties"], 16),
        "_native_legacy_surface_descriptor": int(surf["function"]["descriptor"], 16),
        "_native_legacy_surface_width": int(surf["function"]["width"], 16),
        "_native_legacy_surface_height": int(surf["function"]["height"], 16),
        "_native_legacy_surface_stride": int(surf["function"]["stride"], 16),
        "_native_legacy_surface_allocation": int(surf["function"]["allocation"], 16),
        "_native_legacy_surface_format": int(surf["function"]["format"], 16),
        "_native_legacy_surface_planes": int(surf["function"]["planes"], 16),
    }
    data_bindings = {
        "__ZN25IOMobileFramebufferLegacy10gMetaClassE": int(cls["meta_class"], 16),
        "__ZTV25IOMobileFramebufferLegacy": vtable_va,
    }
    # Add all inherited IOMobileFramebufferLegacy virtual methods referenced by vtable or super-calls
    owned_slots = []
    for s, sym_name in enumerate(compiled_slot_syms):
        if "19NativeLegacyDisplay" in sym_name:
            owned_slots.append(s)
        elif "25IOMobileFramebufferLegacy" in sym_name:
            if orig_vas[s] == pure_va:
                raise SystemExit(f"Pure slot {s} ({sym_name}) was NOT overridden by NativeLegacyDisplay!")
            code_bindings[sym_name] = orig_vas[s]

    # Also bind explicit super-calls (e.g. IOMobileFramebufferLegacy::start, stop, free, newUserClient, setPowerState, getRefreshAttributes, completeCurrentSwap)
    super_slot_map = {
        "__ZN25IOMobileFramebufferLegacy4freeEv": 14,
        "__ZN25IOMobileFramebufferLegacy5startEP9IOService": 86,
        "__ZN25IOMobileFramebufferLegacy4stopEP9IOService": 87,
        "__ZN25IOMobileFramebufferLegacy13newUserClientEP4taskPvjPP12IOUserClient": 141,
        "__ZN25IOMobileFramebufferLegacy13setPowerStateEmP9IOService": 155,
        "__ZN25IOMobileFramebufferLegacy19completeCurrentSwapEv": 312,
        "__ZN25IOMobileFramebufferLegacy20getRefreshAttributesEPyb": 319,
    }
    for sym_name, s in super_slot_map.items():
        if sym_name in undefined:
            code_bindings[sym_name] = orig_vas[s]

    # Verify zero unbound IOMobileFramebufferLegacy symbols remain
    legacy_undef = {n for n in undefined if "25IOMobileFramebufferLegacy" in n}
    missing_legacy = legacy_undef - set(code_bindings) - set(data_bindings)
    if missing_legacy:
        raise SystemExit(f"Unbound IOMobileFramebufferLegacy symbols: {sorted(missing_legacy)}")

    slide = args.collection_slide
    stubs_lines = [".text", ".p2align 2"]
    addrs_lines = []
    for sym_name, orig_va in sorted(code_bindings.items()):
        if sym_name not in undefined:
            continue
        slid = orig_va + slide
        addrs_lines.append(f".globl {sym_name}.original")
        addrs_lines.append(f".set {sym_name}.original, {slid:#x}")
        stubs_lines.append(f".globl {sym_name}")
        stubs_lines.append(f"{sym_name}:")
        stubs_lines.append("    bti c")
        stubs_lines.append(f"    b {sym_name}.original")
    for sym_name, orig_va in sorted(data_bindings.items()):
        if sym_name not in undefined:
            continue
        slid = orig_va + slide
        addrs_lines.append(f".globl {sym_name}")
        addrs_lines.append(f".set {sym_name}, {slid:#x}")

    stubs_s = out / "NativeLegacyDisplay24A446Stubs.S"
    addrs_s = out / "NativeLegacyDisplay24A446Addrs.S"
    stubs_o = out / "NativeLegacyDisplay24A446Stubs.o"
    addrs_o = out / "NativeLegacyDisplay24A446Addrs.o"
    stubs_s.write_text("\n".join(stubs_lines) + "\n")
    addrs_s.write_text("\n".join(addrs_lines) + "\n")

    sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
    subprocess.run(["xcrun", "clang", "-target", TRIPLE, "-isysroot", sdk, "-c", str(stubs_s), "-o", str(stubs_o)], check=True)
    subprocess.run(["xcrun", "clang", "-target", TRIPLE, "-isysroot", sdk, "-c", str(addrs_s), "-o", str(addrs_o)], check=True)
    check_object(stubs_o.read_bytes(), "NativeLegacyDisplay24A446Stubs.o")

    # 5) Remove __DATA,__mod_init_func and globalize __GLOBAL__sub_I_NativeLegacyDisplay.cpp
    late_obj = out / "NativeLegacyDisplay.late.o"
    objcopy = "llvm-objcopy-21" if subprocess.run(["which", "llvm-objcopy-21"], capture_output=True).returncode == 0 else "llvm-objcopy"
    subprocess.run([
        objcopy,
        "--remove-section=__DATA,__mod_init_func",
        "--globalize-symbol=__GLOBAL__sub_I_NativeLegacyDisplay.cpp",
        str(pac_obj),
        str(late_obj),
    ], check=True)
    late_bytes = late_obj.read_bytes()
    check_object(late_bytes, "NativeLegacyDisplay.late.o")

    late_secs, late_syms = parse_macho_object(late_bytes)
    if any(s["name"] == "__mod_init_func" for s in late_secs):
        raise SystemExit("__DATA,__mod_init_func was NOT removed from NativeLegacyDisplay.late.o")
    init_sym = next((s for s in late_syms if s["name"] == "___GLOBAL__sub_I_NativeLegacyDisplay.cpp" or s["name"] == "__GLOBAL__sub_I_NativeLegacyDisplay.cpp"), None)
    # Wait: check exact symbol name (Mach-O prefixes C/C++ symbols with '_')
    if init_sym is None:
        cand = [s["name"] for s in late_syms if "GLOBAL__sub_I_NativeLegacyDisplay" in s["name"]]
        raise SystemExit(f"Could not locate globalized initializer symbol; candidates={cand}")
    if not (init_sym["type"] & 1):
        # Retry with exact leading underscore if llvm-objcopy needed _ prefix
        subprocess.run([
            objcopy,
            "--remove-section=__DATA,__mod_init_func",
            f"--globalize-symbol={init_sym['name']}",
            str(pac_obj),
            str(late_obj),
        ], check=True)
        late_bytes = late_obj.read_bytes()
        _, late_syms = parse_macho_object(late_bytes)
        init_sym = next(s for s in late_syms if s["name"] == init_sym["name"])
        if not (init_sym["type"] & 1):
            raise SystemExit(f"Initializer {init_sym['name']} is still local (type={init_sym['type']:#x})")

    # 5b) Compile ViolinLegacyDisplayProbe.cpp (-Wall -Wextra -Werror)
    probe_src = args.probe.resolve()
    probe_obj = out / "ViolinLegacyDisplayProbe.o"
    probe_cmd = []
    i = 0
    while i < len(args_list):
        v = args_list[i]
        if v == record["file"]:
            probe_cmd.append(str(probe_src))
        elif v == "-o":
            probe_cmd.extend(["-o", str(probe_obj)])
            i += 1
        elif v in ("-MF", "-MT", "-MQ", "-MJ"):
            i += 1
        elif v in ("-MD", "-MMD", "-MP"):
            pass
        elif v == "-Xclang" and i + 1 < len(args_list) and args_list[i + 1].startswith("-W"):
            i += 1
        elif not v.startswith("-W"):
            probe_cmd.append(v)
        i += 1
    probe_cmd.extend([
        "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-parameter", "-Wno-c99-designator", "-Wno-reorder-init-list",
        "-Wno-deprecated-enum-enum-conversion", "-Wno-unnecessary-virtual-specifier",
        "-Wno-missing-designated-field-initializers", "-Wno-unused-but-set-global",
        "-I", str(tree / ".cache/xnu-work/osfmk"),
    ])
    res_p = subprocess.run(probe_cmd, cwd=record["directory"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    (out / "probe-compile.log").write_text(res_p.stdout)
    if res_p.returncode != 0:
        raise SystemExit(f"ViolinLegacyDisplayProbe.cpp compile failed:\n{res_p.stdout[-4000:]}")
    check_object(probe_obj.read_bytes(), "ViolinLegacyDisplayProbe.o")

    # 6) Archive with xcrun ar + ranlib (Mach-O __.SYMDEF TOC)
    archive = out / "libNativeLegacyDisplay.late.a"
    archive.unlink(missing_ok=True)
    subprocess.run(["xcrun", "ar", "rcs", str(archive), str(late_obj), str(stubs_o), str(addrs_o), str(probe_obj)], check=True)
    subprocess.run(["xcrun", "ranlib", str(archive)], check=True)

    report = {
        "target": TRIPLE,
        "kernelcache_sha256": kc_sha,
        "collection_slide": hex(slide),
        "source_sha256": {
            "drivers/GopFramebuffer/NativeLegacyDisplay.cpp": sha256_file(source),
            "drivers/GopFramebuffer/NativeLegacyRequest.h": sha256_file(source.with_name("NativeLegacyRequest.h")),
            "drivers/GopFramebuffer/NativeGOPWire.h": sha256_file(source.with_name("NativeGOPWire.h")),
        },
        "generated_abi_sha256": sha256_file(abi_header_path),
        "raw_object_sha256": sha256_file(raw_obj),
        "pac_object_sha256": sha256_file(pac_obj),
        "late_object_sha256": sha256_file(late_obj),
        "archive_sha256": sha256_file(archive),
        "initializer_symbol": init_sym["name"],
        "virtual_entries": slots,
        "owned_entries": owned_slots,
        "guarded_leaves": GUARDED_LEAVES,
        "code_stubs_count": sum(1 for k in code_bindings if k in undefined),
        "data_bindings": {k: hex(v) for k, v in sorted(data_bindings.items()) if k in undefined},
        "pac_audit": pac_audit,
        "original_instructions_modified": False,
    }
    report_path = out / "build-report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: libNativeLegacyDisplay.late.a built & strictly PAC-audited ({TRIPLE})")
    print(f"  archive: {archive} ({archive.stat().st_size} B, sha256={report['archive_sha256'][:16]}...)")
    print(f"  initializer: {init_sym['name']} (global, __mod_init_func removed)")
    print(f"  vtable: {slots} slots (0..167 mismatches=0, 168..378 rewritten={pac_audit['vtable_subclass_168_378_rewritten']})")
    print(f"  callsites: base(<168)={pac_audit['callsites_base_lt_168_audited']}, patched(>=168)={len(pac_audit['callsites_subclass_ge_168_patched'])}")
    for cs in pac_audit["callsites_subclass_ge_168_patched"]:
        print(f"    {cs['op']} slot {cs['slot']} ({cs['method']}) in {cs['func']}+{cs['offset']}: {cs['old_div']} -> {cs['new_div']}")
    print(f"  stubs: {report['code_stubs_count']} BTI/B original stubs, {len(report['data_bindings'])} data bindings")


if __name__ == "__main__":
    main()
