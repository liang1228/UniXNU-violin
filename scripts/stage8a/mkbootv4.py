#!/usr/bin/env python3
"""Pack a bare-metal ARM64 Image into an Android Boot Image v4 matching violin boot_a."""

import argparse
import hashlib
import struct
from pathlib import Path

BOOT_MAGIC = b"ANDROID!"
BOOT_IMG_HDR_V4_SIZE = 1584
PAGE_SIZE = 4096


def align_up(n: int, align: int) -> int:
    return (n + align - 1) & ~(align - 1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kernel", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--cmdline", default="")
    ap.add_argument("--os-version", default=0, type=lambda s: int(s, 0))
    args = ap.parse_args()

    kernel = args.kernel.read_bytes()
    if len(kernel) < 64 or kernel[56:60] != b"ARMd":
        raise SystemExit("ERROR: kernel payload missing ARM64 Image magic 'ARM\\x64' at +0x38")

    cmdline_bytes = args.cmdline.encode("ascii")
    if len(cmdline_bytes) >= 1536:
        raise SystemExit("ERROR: cmdline too long for v4 header")
    cmdline_padded = cmdline_bytes + b"\x00" * (1536 - len(cmdline_bytes))

    # struct boot_img_hdr_v4 (AOSP bootimg.h):
    #   char     magic[8]           ("ANDROID!")
    #   uint32_t kernel_size
    #   uint32_t ramdisk_size       (0)
    #   uint32_t os_version         (0, matches stock boot_a)
    #   uint32_t header_size        (1584)
    #   uint32_t reserved[4]        (0,0,0,0)
    #   uint32_t header_version     (4)
    #   char     cmdline[1536]
    #   uint32_t signature_size     (0)
    hdr = struct.pack(
        "<8sIIIIIIIII1536sI",
        BOOT_MAGIC,
        len(kernel),
        0,
        args.os_version,
        BOOT_IMG_HDR_V4_SIZE,
        0,
        0,
        0,
        0,
        4,
        cmdline_padded,
        0,
    )
    assert len(hdr) == BOOT_IMG_HDR_V4_SIZE, f"unexpected hdr size {len(hdr)}"

    hdr_page = hdr + b"\x00" * (PAGE_SIZE - len(hdr))
    kernel_padded = kernel + b"\x00" * (align_up(len(kernel), PAGE_SIZE) - len(kernel))
    out = hdr_page + kernel_padded
    args.output.write_bytes(out)

    print(f"Wrote {args.output} ({len(out)} bytes)")
    print(f"  header_version = 4, header_size = {BOOT_IMG_HDR_V4_SIZE}")
    print(f"  kernel_size    = {len(kernel)} (padded {len(kernel_padded)})")
    print(f"  kernel_magic   = {kernel[0:2]!r} / {kernel[56:60]!r}")
    print(f"  sha256         = {hashlib.sha256(out).hexdigest()}")


if __name__ == "__main__":
    main()
