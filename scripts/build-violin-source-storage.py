#!/usr/bin/env python3
"""Build Stage-7G arm64e libViolinSourceStorage.a with strict 190/190 PAC audit.

Compiles (zero edits to upstream source/UniXNU):
  1. Pinned IOStorageFamily (7edb88fb) IOBlockStorageDevice.cpp with late-bound
     metaclass "UniXNUBlockStorageDevice" -> parent native_source_storage_parent()
  2. Strictly Read-Only XringUfsBlock.cpp (LUN 2 UFSHCI 4.0)
  3. Upstream read-only NativeKeyStoreEvents.cpp (AppleKeyStoreState)
  4. Board KeyStoreGlue.cpp + ViolinStorageProbe.cpp

Audits all 190 arm64e PAC vtable slot diversities of both IOBlockStorageDevice
and XringUfsBlock directly against 24A446 kernelcache.decompressed IOStorageFamily
(requiring 0 diffs), strips __DATA,__mod_init_func and globalizes static
constructors for deferred preModLoad/postModLoad registration, and emits
libViolinSourceStorage.a + violin-source-storage-build-report.json.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys


EXPECTED_IOSTORAGEFAMILY_COMMIT = "7edb88fbae296fb7c8ce2f64e115e116e566d51c"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def parse_macho_object(data: bytes):
    magic, cpu, _, filetype, ncmds, _, _, _ = struct.unpack_from("<8I", data, 0)
    if magic != 0xFEEDFACF or cpu != 0x0100000C or filetype != 1:
        raise SystemExit(f"Not an arm64/arm64e MH_OBJECT (magic={magic:#x} cpu={cpu:#x} type={filetype})")
    sections = []
    symbols = []
    pos = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<2I", data, pos)
        if cmd == 0x19:
            nsects = struct.unpack_from("<I", data, pos + 64)[0]
            spos = pos + 72
            for _ in range(nsects):
                sname = data[spos : spos + 16].split(b"\0", 1)[0].decode()
                segname = data[spos + 16 : spos + 32].split(b"\0", 1)[0].decode()
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
        elif cmd == 0x2:
            symoff, nsyms, stroff, _ = struct.unpack_from("<4I", data, pos + 8)
            for idx in range(nsyms):
                strx, ntype, nsect, ndesc, nval = struct.unpack_from("<IBBHQ", data, symoff + idx * 16)
                end = data.index(b"\0", stroff + strx)
                symbols.append({
                    "index": idx,
                    "name": data[stroff + strx : end].decode(),
                    "type": ntype,
                    "sect": nsect,
                    "desc": ndesc,
                    "val": nval,
                })
        pos += cmdsize
    return sections, symbols


def extract_obj_vtable_divs(raw_obj: bytes, ztv_name: str) -> list[tuple[int, str, int]]:
    sections, symbols = parse_macho_object(raw_obj)
    vt_sym = next((s for s in symbols if s["name"] == ztv_name and s["sect"] != 0), None)
    if vt_sym is None:
        raise SystemExit(f"Missing vtable symbol {ztv_name}")
    vt_sec = sections[vt_sym["sect"] - 1]
    vt_off = vt_sym["val"] - vt_sec["addr"]
    next_offs = sorted(
        s["val"] - vt_sec["addr"]
        for s in symbols
        if s["sect"] == vt_sym["sect"] and (s["val"] - vt_sec["addr"]) > vt_off
    )
    vt_end = next_offs[0] if next_offs else vt_sec["size"]

    slots = {}
    for i in range(vt_sec["nreloc"]):
        r_addr, r_info = struct.unpack_from("<2I", raw_obj, vt_sec["reloff"] + i * 8)
        r_sym = r_info & 0xFFFFFF
        r_type = (r_info >> 28) & 0xF
        if vt_off + 16 <= r_addr < vt_end and (r_addr - (vt_off + 16)) % 8 == 0:
            slot = (r_addr - (vt_off + 16)) // 8
            if r_type != 11:
                raise SystemExit(f"{ztv_name} slot {slot}: expected ARM64_RELOC_AUTHENTICATED_POINTER (11), got {r_type}")
            w = struct.unpack_from("<Q", raw_obj, vt_sec["offset"] + r_addr)[0]
            auth, key, ad, div, addend = (w >> 63) & 1, (w >> 49) & 3, (w >> 48) & 1, (w >> 32) & 0xFFFF, w & 0xFFFFFFFF
            if (auth, key, ad, addend) != (1, 0, 1, 0):
                raise SystemExit(f"{ztv_name} slot {slot}: unexpected auth encoding {w:#018x}")
            slots[slot] = (symbols[r_sym]["name"], div)
    nslots = len(slots)
    if set(slots) != set(range(nslots)):
        raise SystemExit(f"{ztv_name}: non-contiguous vtable slots")
    return [(s, slots[s][0], slots[s][1]) for s in range(nslots)]


def find_24a446_ioblockstoragedevice_vtable(kc_bytes: bytes, unixnu: Path, expected_divs: list[int]) -> dict:
    sys.path.insert(0, str(unixnu / "kits/XnuPrelink"))
    from kc_image import Image as KCImage

    kc = KCImage(kc_bytes)
    fixups = kc.fixups()

    pos = 32
    ncmds = struct.unpack_from("<I", kc_bytes, 16)[0]
    iosf_fo = None
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from("<2I", kc_bytes, pos)
        if cmd == 0x80000035:
            _, fo, so = struct.unpack_from("<QQI", kc_bytes, pos + 8)
            nm = kc_bytes[pos + so : kc_bytes.index(b"\0", pos + so)].decode()
            if nm == "com.apple.iokit.IOStorageFamily":
                iosf_fo = fo
                break
        pos += sz
    if iosf_fo is None:
        raise SystemExit("com.apple.iokit.IOStorageFamily not found in kernelcache")

    p = iosf_fo + 32
    n = struct.unpack_from("<I", kc_bytes, iosf_fo + 16)[0]
    dc_vm = dc_vmsz = 0
    for _ in range(n):
        cmd, sz = struct.unpack_from("<2I", kc_bytes, p)
        if cmd == 0x19:
            sn = kc_bytes[p + 8 : p + 24].split(b"\0", 1)[0].decode()
            if sn == "__DATA_CONST":
                dc_vm, dc_vmsz = struct.unpack_from("<2Q", kc_bytes, p + 24)
                break
        p += sz

    nslots = len(expected_divs)
    perfect = []
    for va in range(dc_vm, dc_vm + dc_vmsz - (nslots + 2) * 8, 8):
        if (va in fixups) or ((va + 8) in fixups) or ((va + 16) not in fixups):
            continue
        ok = True
        for s in range(nslots):
            f = fixups.get(va + 16 + s * 8)
            if not f or f[1] != 1 or f[2] != 0 or f[4] != 1 or f[3] != expected_divs[s]:
                ok = False
                break
        if not ok:
            continue
        # Ensure vtable ends right at nslots (next qword is not an auth slot)
        nxt = fixups.get(va + 16 + nslots * 8)
        if nxt and nxt[1] == 1:
            continue
        targets = [fixups[va + 16 + s * 8][0] for s in range(nslots)]
        # Pure-virtual base IOBlockStorageDevice has 14 identical pure_virtual targets
        pure_count = sum(1 for s in range(168, nslots) if targets[s] == targets[168])
        perfect.append((va, pure_count))

    if not perfect:
        raise SystemExit("No 190/190 PAC-matching IOBlockStorageDevice vtable found in 24A446 IOStorageFamily")
    base_candidates = [va for va, pc in perfect if pc == 14]
    if len(base_candidates) != 1:
        raise SystemExit(f"Expected 1 abstract IOBlockStorageDevice vtable (14 pure slots), found {perfect}")
    return {
        "vtable_va": hex(base_candidates[0]),
        "slots": nslots,
        "matching_vtables_in_iostoragefamily": [hex(va) for va, _ in perfect],
    }


def make_compile_cmd(record: dict, src: Path, out_o: Path, extra_flags: list[str]) -> list[str]:
    cmd = []
    args = record["arguments"]
    i = 0
    while i < len(args):
        v = args[i]
        if v == record["file"]:
            cmd.append(str(src))
        elif v == "-o":
            cmd.extend(["-o", str(out_o)])
            i += 1
        elif v in ("-MF", "-MT", "-MQ", "-MJ"):
            i += 1
        elif v in ("-MD", "-MMD", "-MP"):
            pass
        elif v == "-Xclang" and i + 1 < len(args) and args[i + 1].startswith("-W"):
            i += 1
        elif not v.startswith("-W"):
            cmd.append(v)
        i += 1
    cmd.extend(extra_flags)
    return cmd


def find_tool(names: list[str]) -> str:
    for n in names:
        p = subprocess.run(["which", n], capture_output=True, text=True)
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.strip()
    raise SystemExit(f"Required tool not found in PATH: {names}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--unixnu", type=Path, default=Path("/mnt/e/workspace/projects/unixnu-violin/source/UniXNU"))
    ap.add_argument("--common", type=Path, default=Path("/mnt/e/workspace/projects/unixnu-violin/source/UniXNU-xring-o1-common"))
    ap.add_argument("--board", type=Path, default=Path("/mnt/e/workspace/projects/unixnu-violin/source/UniXNU-violin"))
    ap.add_argument("--tree", type=Path, default=Path("/opt/unixnu-out/violin/ipados-27.0.1-24A446/violin/tree"))
    ap.add_argument("--kernelcache", type=Path, default=Path("/opt/unixnu-out/ipsw/24A446/kernelcache.decompressed"))
    ap.add_argument("--out-dir", type=Path, default=Path("/opt/unixnu-out/stage7g-storage/source-storage"))
    args = ap.parse_args()

    unixnu = args.unixnu.resolve()
    common = args.common.resolve()
    board = args.board.resolve()
    tree = args.tree.resolve()
    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)

    storage_src = (tree / "refer/IOStorageFamily").resolve()
    rev = subprocess.check_output(["git", "-C", str(storage_src), "rev-parse", "HEAD"], text=True).strip()
    if rev != EXPECTED_IOSTORAGEFAMILY_COMMIT:
        raise SystemExit(f"Unexpected IOStorageFamily commit {rev} != {EXPECTED_IOSTORAGEFAMILY_COMMIT}")

    storage_inc = tree / "build/storage-abi/include"
    if not (storage_inc / "IOKit/storage/IOBlockStorageDevice.h").is_file():
        raise SystemExit(f"Missing storage-abi headers at {storage_inc}")

    os.environ["UNIXNU_XNU_ARCH"] = "arm64e"
    os.environ["UNIXNU_IOS_VERSION"] = "27.0.1"
    kt = load_module("kernel_target", unixnu / "scripts/kernel_target.py")
    if kt.ARCH != "arm64e":
        raise SystemExit(f"Expected arm64e, got {kt.ARCH}")

    cpp_rec = json.loads(
        (tree / "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json")
        .read_text()
        .strip()
        .rstrip(",")
    )

    # 1. Generate late-bound IOBlockStorageDevice.cpp ("UniXNUBlockStorageDevice")
    orig_bsd = (storage_src / "IOBlockStorageDevice.cpp").read_text()
    macro = "OSDefineMetaClassAndAbstractStructors(IOBlockStorageDevice,IOService)"
    if orig_bsd.count(macro) != 1:
        raise SystemExit("Pinned IOBlockStorageDevice macro changed")
    late_bsd = out / "IOBlockStorageDevice.cpp"
    late_bsd.write_text(
        orig_bsd.replace(
            macro,
            '\nextern "C" const OSMetaClass *native_source_storage_parent(void);\n'
            "OSDefineMetaClassWithInit(IOBlockStorageDevice, IOService, )\n"
            "IOBlockStorageDevice::MetaClass::MetaClass()\n"
            '    : OSMetaClass("UniXNUBlockStorageDevice", native_source_storage_parent(), sizeof(IOBlockStorageDevice)) {}\n'
            "OSDefineAbstractStructors(IOBlockStorageDevice, IOService)\n"
            "OSDefineOperatorMethods(IOBlockStorageDevice)\n",
        )
    )

    base_includes = [
        "-I", str(storage_inc),
        "-I", str(tree / ".cache/xnu-work/osfmk"),
        "-I", str(common / "drivers/XringUfs"),
        "-I", str(unixnu / "drivers/RamBlock"),
    ]
    strict_flags = base_includes + [
        "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-parameter", "-Wno-c99-designator", "-Wno-reorder-init-list",
        "-Wno-deprecated-enum-enum-conversion", "-Wno-unnecessary-virtual-specifier",
        "-Wno-deprecated-declarations", "-Wno-missing-designated-field-initializers",
    ]
    permissive_flags = base_includes + ["-Wno-error"]

    units = [
        ("IOBlockStorageDevice", late_bsd, permissive_flags, "__GLOBAL__sub_I_IOBlockStorageDevice.cpp"),
        ("XringUfsBlock", common / "drivers/XringUfs/XringUfsBlock.cpp", strict_flags, "__GLOBAL__sub_I_XringUfsBlock.cpp"),
        ("NativeRamBlock", unixnu / "drivers/RamBlock/NativeRamBlock.cpp", permissive_flags, "__GLOBAL__sub_I_NativeRamBlock.cpp"),
        ("NativeKeyStoreEvents", unixnu / "drivers/AppleKeyStoreState/NativeKeyStoreEvents.cpp", permissive_flags, None),
        ("KeyStoreGlue", board / "drivers/ViolinStorage/KeyStoreGlue.cpp", strict_flags, None),
        ("ViolinStorageProbe", board / "drivers/ViolinStorage/ViolinStorageProbe.cpp", strict_flags, None),
    ]

    objcopy = find_tool(["llvm-objcopy", "llvm-objcopy-21", "llvm-objcopy-20", "llvm-objcopy-19"])
    ar = find_tool(["llvm-ar", "llvm-ar-21", "llvm-ar-20", "ar"])

    compiled_raw = {}
    final_objs = []
    obj_reports = {}

    for name, src, flg, late_ctor in units:
        raw_o = out / f"{name}.o"
        cmd = make_compile_cmd(cpp_rec, src, raw_o, flg)
        res = subprocess.run(cmd, cwd=cpp_rec["directory"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        (out / f"{name}.compile.log").write_text(res.stdout)
        if res.returncode != 0:
            raise SystemExit(f"{name} compile failed:\n{res.stdout[-4000:]}")
        raw_bytes = raw_o.read_bytes()
        kt.check_object(raw_bytes, raw_o.name)
        compiled_raw[name] = raw_bytes

        target_o = raw_o
        if late_ctor is not None:
            _, syms = parse_macho_object(raw_bytes)
            if not any(s["name"] == late_ctor for s in syms):
                ctors = [s["name"] for s in syms if "__GLOBAL__sub_I" in s["name"]]
                raise SystemExit(f"{name}: expected ctor {late_ctor}, found {ctors}")
            late_o = out / f"{name}.late.o"
            subprocess.run(
                [objcopy, "--remove-section=__DATA,__mod_init_func", f"--globalize-symbol={late_ctor}", str(raw_o), str(late_o)],
                check=True,
            )
            kt.check_object(late_o.read_bytes(), late_o.name)
            target_o = late_o

        final_objs.append(target_o)
        obj_reports[name] = {
            "source": str(src),
            "object": str(target_o),
            "bytes": target_o.stat().st_size,
            "sha256": sha256_file(target_o),
            "late_ctor_globalized": late_ctor,
        }

    # 2. Strict 190/190 arm64e PAC diversity audit against 24A446 kernelcache
    bsd_vtable = extract_obj_vtable_divs(compiled_raw["IOBlockStorageDevice"], "__ZTV20IOBlockStorageDevice")
    ufs_vtable = extract_obj_vtable_divs(compiled_raw["XringUfsBlock"], "__ZTV13XringUfsBlock")
    ram_vtable = extract_obj_vtable_divs(compiled_raw["NativeRamBlock"], "__ZTV14NativeRamBlock")
    bsd_divs = [d for _, _, d in bsd_vtable]
    ufs_divs = [d for _, _, d in ufs_vtable]
    ram_divs = [d for _, _, d in ram_vtable]
    if len(bsd_divs) != 190 or len(ufs_divs) != 190 or len(ram_divs) != 190:
        raise SystemExit(
            f"Expected 190 vtable slots, got IOBlockStorageDevice={len(bsd_divs)} "
            f"XringUfsBlock={len(ufs_divs)} NativeRamBlock={len(ram_divs)}"
        )
    ufs_diffs = [(s, bsd_vtable[s][1], ufs_vtable[s][1], hex(bsd_divs[s]), hex(ufs_divs[s]))
                 for s in range(190) if bsd_divs[s] != ufs_divs[s]]
    if ufs_diffs:
        raise SystemExit(f"XringUfsBlock vs IOBlockStorageDevice PAC diversity mismatch: {ufs_diffs[:10]}")
    ram_diffs = [(s, bsd_vtable[s][1], ram_vtable[s][1], hex(bsd_divs[s]), hex(ram_divs[s]))
                 for s in range(190) if bsd_divs[s] != ram_divs[s]]
    if ram_diffs:
        raise SystemExit(f"NativeRamBlock vs IOBlockStorageDevice PAC diversity mismatch: {ram_diffs[:10]}")

    kc_audit = find_24a446_ioblockstoragedevice_vtable(args.kernelcache.read_bytes(), unixnu, bsd_divs)

    # 3. Archive into libViolinSourceStorage.a
    archive = out / "libViolinSourceStorage.a"
    archive.unlink(missing_ok=True)
    subprocess.run([ar, "rcs", str(archive), *[str(o) for o in final_objs]], check=True)

    report = {
        "triple": kt.TRIPLE,
        "iostoragefamily_commit": rev,
        "archive": str(archive),
        "archive_bytes": archive.stat().st_size,
        "archive_sha256": sha256_file(archive),
        "pac_audit": {
            "ioblockstoragedevice_slots": len(bsd_divs),
            "xringufsblock_slots": len(ufs_divs),
            "nativeramblock_slots": len(ram_divs),
            "xringufsblock_vs_base_diffs": 0,
            "nativeramblock_vs_base_diffs": 0,
            "base_vs_24a446_diffs": 0,
            **kc_audit,
        },
        "objects": obj_reports,
    }
    (out / "violin-source-storage-build-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"PASS: libViolinSourceStorage.a ({archive.stat().st_size} B, sha256={report['archive_sha256'][:16]}...) "
        f"| PAC audit 190/190=0 diffs vs 24A446 {kc_audit['vtable_va']}"
    )


if __name__ == "__main__":
    main()
