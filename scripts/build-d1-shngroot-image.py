#!/usr/bin/env python3
"""
Build Dual-Boot D1 SHNGROOT v2 image for Xiaomi Pad 7S Pro (violin, ipados-27.0.1-24A446).

Matches upstream source/UniXNU/scripts/unixnu/userdata.py SHNGROOT v2 wire format byte-for-byte:
  0x000000: 4096-byte SHNGROOT v2 manifest (SHA-256 at [4064..4096)), padded to 1 MiB
  0x100000: Window "OS"             (block_size=512,  flags=1, 1 MiB aligned)
  ...     : Window "SystemOS"       (block_size=512,  flags=1, 1 MiB aligned)
  ...     : Object "OS.vroot"       (block_size=4096, flags=3, 1 MiB aligned) -> full signed manifest.bin
  ...     : Object "SystemOS.vroot" (block_size=4096, flags=3, 1 MiB aligned) -> full signed manifest.bin
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

MIB = 1 << 20
CHUNK = 8 * MIB

DEFAULT_OS = Path("/opt/unixnu-out/ipsw/24A446/OS.raw.dmg")
DEFAULT_SYSOS = Path("/opt/unixnu-out/ipsw/24A446/SystemOS.raw.dmg")
DEFAULT_OS_VROOT = Path("/opt/unixnu-out/stage7h-apfs/verified-root-24A446-work/verified-root-OS/manifest.bin")
DEFAULT_SYS_VROOT = Path("/opt/unixnu-out/stage7h-apfs/verified-root-24A446-work/verified-root-SystemOS/manifest.bin")
DEFAULT_OUT = Path("/opt/unixnu-out/stage7n-dualboot-d1/violin-d1-shngroot-24A446.img")
DEFAULT_REPORT = Path("/opt/unixnu-out/stage7n-dualboot-d1/violin-d1-shngroot-24A446.json")


def align_mib(n: int) -> int:
    return (n + MIB - 1) // MIB * MIB


def stream_copy_and_hash(src: Path, dst_fh, offset: int) -> tuple[int, bytes]:
    dst_fh.seek(offset)
    h = hashlib.sha256()
    total = 0
    with src.open("rb") as sf:
        while True:
            buf = sf.read(CHUNK)
            if not buf:
                break
            h.update(buf)
            dst_fh.write(buf)
            total += len(buf)
    return total, h.digest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--os", type=Path, default=DEFAULT_OS)
    ap.add_argument("--sysos", type=Path, default=DEFAULT_SYSOS)
    ap.add_argument("--os-vroot", type=Path, default=DEFAULT_OS_VROOT)
    ap.add_argument("--sys-vroot", type=Path, default=DEFAULT_SYS_VROOT)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    ap.add_argument("--tail-gib", type=int, default=128)
    args = ap.parse_args()

    items = [
        ("OS", args.os, 512, 1),
        ("SystemOS", args.sysos, 512, 1),
        ("OS.vroot", args.os_vroot, 4096, 3),
        ("SystemOS.vroot", args.sys_vroot, 4096, 3),
    ]
    for name, p, _, _ in items:
        if not p.is_file():
            raise SystemExit(f"Missing input {name}: {p}")

    cursor = MIB
    layout = []
    for name, p, blk, flg in items:
        sz = p.stat().st_size
        layout.append((name, p, cursor, sz, blk, flg))
        cursor += align_mib(sz)

    total_bytes = cursor
    tail_bytes = args.tail_gib * (1 << 30)
    if total_bytes + (4 << 20) + (1 << 30) > tail_bytes:
        raise SystemExit(f"Image {total_bytes} B exceeds tail capacity {tail_bytes} B")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    print(f"Building SHNGROOT v2 image -> {args.out} ({total_bytes} B = {total_bytes / (1<<30):.2f} GiB)...", flush=True)

    header = bytearray(4096)
    header[0:8] = b"SHNGROOT"
    struct.pack_into("<IIQ", header, 8, 2, len(layout), total_bytes)

    report_entries = []
    with args.out.open("wb") as out_fh:
        out_fh.truncate(total_bytes)
        for idx, (name, p, off, sz, blk, flg) in enumerate(layout):
            print(f"  [{idx}] streaming {name} ({sz} B) @ 0x{off:x}...", flush=True)
            copied, digest = stream_copy_and_hash(p, out_fh, off)
            assert copied == sz
            struct.pack_into("<32sQQII32s40s", header, 24 + 128 * idx,
                             name.encode("ascii"), off, sz, blk, flg, digest, bytes(40))
            report_entries.append({
                "name": name, "offset": off, "size": sz,
                "block_size": blk, "flags": flg, "sha256": digest.hex(),
            })
            print(f"      done sha256={digest.hex()[:16]}..", flush=True)

        header[4064:4096] = hashlib.sha256(bytes(header[:4064])).digest()
        out_fh.seek(0)
        out_fh.write(header)

    rep = {
        "format": "SHNGROOT v2",
        "tail_gib": args.tail_gib,
        "image_path": str(args.out),
        "image_bytes": total_bytes,
        "manifest_header_sha256": hashlib.sha256(bytes(header)).hexdigest(),
        "entries": report_entries,
    }
    args.report.write_text(json.dumps(rep, indent=2) + "\n")
    print(f"SHNGROOT_V2_READY -> {args.out} ({total_bytes} B, hdr_sha256={rep['manifest_header_sha256'][:16]}..)", flush=True)


if __name__ == "__main__":
    main()
