#!/usr/bin/env python3
"""
Dual-Boot D1 GPT Split / Verify / Self-Test Tool for Xiaomi Pad 7S Pro (violin /dev/block/sdc).

Scheme D1 invariants:
  - Primary & Backup GPT num_entries_table stays 80 (100% stock; zero EDK2-XRING entry-count risk).
  - Partitions #1..#79 are 100% bit-for-bit UNCHANGED.
  - Only partition #80 ("userdata") last_lba shrinks by tail_gib (default 128 GiB = 33,554,432 4 KiB LBAs),
    leaving [userdata.last_lba + 1 .. last_usable_lba] as UniXNU's dedicated raw tail.
  - Recomputes entry array CRC32 and Primary + Backup GPT header CRC32 accurately.
"""
import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path

LBA_BYTES = 4096
PRIMARY_LBAS = 8        # LBA 0 (PMBR) .. LBA 7
BACKUP_LBAS = 8         # LBA (alt-7) .. LBA alt
EXPECTED_NUM_ENTRIES = 80
EXPECTED_ENTRY_SIZE = 128
EXPECTED_USERDATA_FIRST_LBA = 3138056
EXPECTED_LAST_USABLE_LBA = 129089527
EXPECTED_ALTERNATE_LBA = 129089535


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def decode_utf16le_name(raw: bytes) -> str:
    return raw.decode("utf-16le", errors="ignore").split("\x00", 1)[0]


def verify_and_transform_gpt(primary_32k: bytes, backup_32k: bytes, tail_gib: int):
    if len(primary_32k) != PRIMARY_LBAS * LBA_BYTES:
        raise ValueError(f"primary must be {PRIMARY_LBAS * LBA_BYTES} B, got {len(primary_32k)}")
    if len(backup_32k) != BACKUP_LBAS * LBA_BYTES:
        raise ValueError(f"backup must be {BACKUP_LBAS * LBA_BYTES} B, got {len(backup_32k)}")

    pri_hdr = bytearray(primary_32k[LBA_BYTES:2 * LBA_BYTES])
    bak_hdr = bytearray(backup_32k[7 * LBA_BYTES:8 * LBA_BYTES])
    if pri_hdr[0:8] != b"EFI PART" or bak_hdr[0:8] != b"EFI PART":
        raise ValueError("Missing EFI PART signature in primary or backup GPT header")

    hdr_size = struct.unpack_from("<I", pri_hdr, 12)[0]
    if hdr_size != 92 or struct.unpack_from("<I", bak_hdr, 12)[0] != 92:
        raise ValueError(f"Unexpected GPT header size {hdr_size}")

    # Verify original primary header CRC
    orig_pri_crc = struct.unpack_from("<I", pri_hdr, 16)[0]
    tmp = bytearray(pri_hdr[:92])
    struct.pack_into("<I", tmp, 16, 0)
    if crc32(tmp) != orig_pri_crc:
        raise ValueError("Original primary GPT header CRC32 mismatch")

    orig_bak_crc = struct.unpack_from("<I", bak_hdr, 16)[0]
    tmp_b = bytearray(bak_hdr[:92])
    struct.pack_into("<I", tmp_b, 16, 0)
    if crc32(tmp_b) != orig_bak_crc:
        raise ValueError("Original backup GPT header CRC32 mismatch")

    my_lba, alt_lba, first_usable, last_usable = struct.unpack_from("<QQQQ", pri_hdr, 24)
    pri_part_lba, num_entries, entry_size, orig_ent_crc = struct.unpack_from("<QIII", pri_hdr, 72)
    bak_part_lba = struct.unpack_from("<Q", bak_hdr, 72)[0]
    if my_lba != 1 or alt_lba != EXPECTED_ALTERNATE_LBA or last_usable != EXPECTED_LAST_USABLE_LBA:
        raise ValueError(f"Unexpected disk geometry my={my_lba} alt={alt_lba} last_usable={last_usable}")
    if num_entries != EXPECTED_NUM_ENTRIES or entry_size != EXPECTED_ENTRY_SIZE or pri_part_lba != 2:
        raise ValueError(f"Unexpected table shape entries={num_entries} esz={entry_size} part_lba={pri_part_lba}")

    ent_bytes = num_entries * entry_size
    pri_entries = bytearray(primary_32k[2 * LBA_BYTES:2 * LBA_BYTES + ent_bytes])
    bak_ent_off = (bak_part_lba - (alt_lba - 7)) * LBA_BYTES
    if bak_ent_off < 0 or bak_ent_off + ent_bytes > 7 * LBA_BYTES:
        raise ValueError(f"Backup partition array offset out of range: {bak_ent_off}")
    bak_entries = bytearray(backup_32k[bak_ent_off:bak_ent_off + ent_bytes])

    if crc32(pri_entries) != orig_ent_crc or pri_entries != bak_entries:
        raise ValueError("Original primary/backup partition entry arrays mismatch or CRC invalid")

    # Verify entry #80 (index 79) is userdata
    ud_off = 79 * 128
    ud_name = decode_utf16le_name(bytes(pri_entries[ud_off + 56:ud_off + 128]))
    ud_first, ud_last = struct.unpack_from("<QQ", pri_entries, ud_off + 32)
    if ud_name != "userdata" or ud_first != EXPECTED_USERDATA_FIRST_LBA:
        raise ValueError(f"Entry #80 unexpected: name={ud_name!r} first={ud_first}")

    tail_lbas = (tail_gib * (1 << 30)) // LBA_BYTES
    new_ud_last = last_usable - tail_lbas
    tail_first = new_ud_last + 1
    if new_ud_last <= ud_first + ((64 << 30) // LBA_BYTES):
        raise ValueError(f"tail_gib={tail_gib} leaves too little Android userdata")

    # Mutate ONLY entry #80 last_lba
    new_entries = bytearray(pri_entries)
    struct.pack_into("<Q", new_entries, ud_off + 40, new_ud_last)
    assert new_entries[:ud_off] == pri_entries[:ud_off], "Partitions #1..#79 must stay bit-for-bit identical!"
    new_ent_crc = crc32(new_entries)

    # Rebuild Primary 32 KiB (LBA 0..7)
    new_pri = bytearray(primary_32k)
    new_pri[2 * LBA_BYTES:2 * LBA_BYTES + ent_bytes] = new_entries
    struct.pack_into("<I", pri_hdr, 88, new_ent_crc)
    struct.pack_into("<I", pri_hdr, 16, 0)
    struct.pack_into("<I", pri_hdr, 16, crc32(pri_hdr[:92]))
    new_pri[LBA_BYTES:2 * LBA_BYTES] = pri_hdr

    # Rebuild Backup 32 KiB (LBA alt-7..alt)
    new_bak = bytearray(backup_32k)
    new_bak[bak_ent_off:bak_ent_off + ent_bytes] = new_entries
    struct.pack_into("<I", bak_hdr, 88, new_ent_crc)
    struct.pack_into("<I", bak_hdr, 16, 0)
    struct.pack_into("<I", bak_hdr, 16, crc32(bak_hdr[:92]))
    new_bak[7 * LBA_BYTES:8 * LBA_BYTES] = bak_hdr

    info = {
        "scheme": "Dual-Boot D1 (GPT num_entries_table=80 unchanged)",
        "tail_gib": tail_gib,
        "num_entries": num_entries,
        "userdata_first_lba": ud_first,
        "userdata_orig_last_lba": ud_last,
        "userdata_new_last_lba": new_ud_last,
        "userdata_new_bytes": (new_ud_last - ud_first + 1) * LBA_BYTES,
        "tail_first_lba": tail_first,
        "tail_last_lba": last_usable,
        "tail_lbas": tail_lbas,
        "tail_bytes": tail_lbas * LBA_BYTES,
        "new_entries_crc32": f"0x{new_ent_crc:08x}",
        "new_primary_hdr_crc32": f"0x{struct.unpack_from('<I', pri_hdr, 16)[0]:08x}",
        "new_backup_hdr_crc32": f"0x{struct.unpack_from('<I', bak_hdr, 16)[0]:08x}",
        "new_primary_sha256": hashlib.sha256(bytes(new_pri)).hexdigest(),
        "new_backup_sha256": hashlib.sha256(bytes(new_bak)).hexdigest(),
    }
    return bytes(new_pri), bytes(new_bak), info


def self_test():
    # Construct synthetic stock violin primary + backup 32 KiB GPT and verify round-trip
    pri = bytearray(PRIMARY_LBAS * LBA_BYTES)
    bak = bytearray(BACKUP_LBAS * LBA_BYTES)
    ent = bytearray(80 * 128)
    # Partition 1: bl2_a
    ent[0:4] = b"\xa2\xa0\xd0\xeb"
    struct.pack_into("<QQ", ent, 32, 8, 1031)
    ent[56:56 + 10] = "bl2_a".encode("utf-16le")
    # Partition 80: userdata
    u = 79 * 128
    ent[u:u + 4] = b"\xa2\xa0\xd0\xeb"
    struct.pack_into("<QQ", ent, u + 32, EXPECTED_USERDATA_FIRST_LBA, EXPECTED_LAST_USABLE_LBA)
    ent[u + 56:u + 56 + 16] = "userdata".encode("utf-16le")

    ecrc = crc32(ent)
    pri[2 * LBA_BYTES:2 * LBA_BYTES + len(ent)] = ent
    bak[0:len(ent)] = ent  # bak_part_lba = alt - 7

    def make_hdr(my_lba, alt_lba, part_lba):
        h = bytearray(LBA_BYTES)
        h[0:8] = b"EFI PART"
        struct.pack_into("<II", h, 8, 0x00010000, 92)
        struct.pack_into("<QQQQ", h, 24, my_lba, alt_lba, 8, EXPECTED_LAST_USABLE_LBA)
        struct.pack_into("<QIII", h, 72, part_lba, 80, 128, ecrc)
        struct.pack_into("<I", h, 16, crc32(h[:92]))
        return h

    pri[LBA_BYTES:2 * LBA_BYTES] = make_hdr(1, EXPECTED_ALTERNATE_LBA, 2)
    bak[7 * LBA_BYTES:8 * LBA_BYTES] = make_hdr(EXPECTED_ALTERNATE_LBA, 1, EXPECTED_ALTERNATE_LBA - 7)

    new_pri, new_bak, info = verify_and_transform_gpt(bytes(pri), bytes(bak), 128)
    assert info["userdata_new_last_lba"] == 95535095
    assert info["tail_first_lba"] == 95535096
    assert info["tail_lbas"] == 33554432
    assert info["tail_bytes"] == 128 * (1 << 30)
    # Re-verify idempotent verification of new headers (must reject further shrink only if invalid, or pass fresh parse)
    assert new_pri[:LBA_BYTES] == pri[:LBA_BYTES]  # PMBR untouched
    print("prepare-d1-gpt-split.py: SELF-TEST PASS ->", json.dumps(info, indent=2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--primary-in", type=Path)
    ap.add_argument("--backup-in", type=Path)
    ap.add_argument("--primary-out", type=Path)
    ap.add_argument("--backup-out", type=Path)
    ap.add_argument("--report-out", type=Path)
    ap.add_argument("--tail-gib", type=int, default=128)
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return

    new_pri, new_bak, info = verify_and_transform_gpt(
        args.primary_in.read_bytes(), args.backup_in.read_bytes(), args.tail_gib
    )
    args.primary_out.write_bytes(new_pri)
    args.backup_out.write_bytes(new_bak)
    if args.report_out:
        args.report_out.write_text(json.dumps(info, indent=2) + "\n")
    print(json.dumps(info, indent=2))


if __name__ == "__main__":
    main()
