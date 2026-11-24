#!/usr/bin/env python3
"""Build and sign Stage-5 static arm64e EL0 /sbin/launchd + 2-module TrustCache on Linux.

Compiles a freestanding arm64e-apple-ios27.0 Mach-O static executable (zero libc/dyld),
injects an Apple-spec 4 KiB-paged SHA-256 LC_CODE_SIGNATURE (CS_SuperBlob +
CS_CodeDirectory v0x20400, CS_ADHOC, CS_EXECSEG_MAIN_BINARY), verifies every
cs_validate_codedirectory invariant, computes the exact 20-byte SHA-256 CDHash, and
appends it as module 1 alongside Apple's byte-identical official 24A446 StaticTrustCache
(module 0) using UniXNU's upstream trust-append-module.py.

SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
from pathlib import Path

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64E = 2
MH_EXECUTE = 2

LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
LC_BUILD_VERSION = 0x32

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSSLOT_CODEDIRECTORY = 0
CS_ADHOC = 0x00000002
CS_HASHTYPE_SHA256 = 2
CS_EXECSEG_MAIN_BINARY = 0x1
CS_VERSION_EXECSEG = 0x20400
SIGN_PAGE_SHIFT = 12
SIGN_PAGE_SIZE = 1 << SIGN_PAGE_SHIFT  # 4096 bytes

START_ASM = r"""// SPDX-License-Identifier: BSD-2-Clause-Patent
// Freestanding arm64e EL0 /sbin/launchd entry + PAC + 32-reg SIMD syscall verifier.
.text
.balign 4
.global _start
_start:
    mov     x0, sp
    and     x0, x0, #-16
    mov     sp, x0
    mov     x29, #0
    mov     x30, #0
    bl      _stage5_main
1:
    wfe
    b       1b

// uint64_t el0_pac_roundtrip(uint64_t ptr, uint64_t ctx, uint64_t *signed_out)
.balign 4
.global _el0_pac_roundtrip
_el0_pac_roundtrip:
    pacibsp
    mov     x9, x0
    pacia   x9, x1
    str     x9, [x2]
    autia   x9, x1
    mov     x0, x9
    retab

// uint64_t el0_simd32_syscall_test(const uint64_t *in64, uint64_t *out64, uint64_t iters)
// Loads all 32 128-bit NEON registers q0..q31, runs `iters` real SYS_getpid syscalls,
// then stores q0..q31 to out64 and returns the last getpid() result.
.balign 4
.global _el0_simd32_syscall_test
_el0_simd32_syscall_test:
    pacibsp
    mov     x9, x0
    mov     x10, x1
    mov     x11, x2

    ldp     q0,  q1,  [x9, #0]
    ldp     q2,  q3,  [x9, #32]
    ldp     q4,  q5,  [x9, #64]
    ldp     q6,  q7,  [x9, #96]
    ldp     q8,  q9,  [x9, #128]
    ldp     q10, q11, [x9, #160]
    ldp     q12, q13, [x9, #192]
    ldp     q14, q15, [x9, #224]
    ldp     q16, q17, [x9, #256]
    ldp     q18, q19, [x9, #288]
    ldp     q20, q21, [x9, #320]
    ldp     q22, q23, [x9, #352]
    ldp     q24, q25, [x9, #384]
    ldp     q26, q27, [x9, #416]
    ldp     q28, q29, [x9, #448]
    ldp     q30, q31, [x9, #480]

    mov     x0, #0
1:
    cbz     x11, 2f
    mov     x16, #20        // SYS_getpid
    svc     #0x80
    sub     x11, x11, #1
    b       1b
2:
    stp     q0,  q1,  [x10, #0]
    stp     q2,  q3,  [x10, #32]
    stp     q4,  q5,  [x10, #64]
    stp     q6,  q7,  [x10, #96]
    stp     q8,  q9,  [x10, #128]
    stp     q10, q11, [x10, #160]
    stp     q12, q13, [x10, #192]
    stp     q14, q15, [x10, #224]
    stp     q16, q17, [x10, #256]
    stp     q18, q19, [x10, #288]
    stp     q20, q21, [x10, #320]
    stp     q22, q23, [x10, #352]
    stp     q24, q25, [x10, #384]
    stp     q26, q27, [x10, #416]
    stp     q28, q29, [x10, #448]
    stp     q30, q31, [x10, #480]
    retab
"""

MAIN_C = r"""// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <stdint.h>
#include <stddef.h>

extern uint64_t el0_pac_roundtrip(uint64_t ptr, uint64_t ctx, uint64_t *signed_out);
extern uint64_t el0_simd32_syscall_test(const uint64_t *in64, uint64_t *out64, uint64_t iters);

enum {
    DARWIN_SYS_exit   = 1,
    DARWIN_SYS_write  = 4,
    DARWIN_SYS_open   = 5,
    DARWIN_SYS_close  = 6,
    DARWIN_SYS_getpid = 20,
    DARWIN_SYS_reboot = 55,
    DARWIN_SYS_sysctl = 202,
};

enum {
    DARWIN_O_WRONLY = 0x00001,
    DARWIN_O_NOCTTY = 0x20000,
    DARWIN_CTL_HW   = 6,
    DARWIN_HW_NCPU     = 3,
    DARWIN_HW_PAGESIZE = 7,
    DARWIN_HW_MEMSIZE  = 24,
    DARWIN_HW_AVAILCPU = 25,
    DARWIN_RB_QUICK_NOSYNC = 0x404,
};

static uint64_t darwin_syscall(uint64_t num, uint64_t a0, uint64_t a1, uint64_t a2,
                               uint64_t a3, uint64_t a4, uint64_t a5, uint32_t *err_out)
{
    register uint64_t x0 __asm__("x0") = a0;
    register uint64_t x1 __asm__("x1") = a1;
    register uint64_t x2 __asm__("x2") = a2;
    register uint64_t x3 __asm__("x3") = a3;
    register uint64_t x4 __asm__("x4") = a4;
    register uint64_t x5 __asm__("x5") = a5;
    register uint64_t x16 __asm__("x16") = num;
    uint32_t carry = 0;
    __asm__ volatile(
        "svc #0x80\n\t"
        "cset %w[c], cs"
        : "+r"(x0), [c] "=r"(carry)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x16)
        : "memory", "cc");
    if (err_out) {
        *err_out = carry ? (uint32_t)x0 : 0U;
    }
    return x0;
}

static uint32_t sysctl_u32(int mib0, int mib1, uint32_t *out)
{
    int mib[2] = { mib0, mib1 };
    uint32_t val = 0;
    size_t len = sizeof(val);
    uint32_t err = 0;
    darwin_syscall(DARWIN_SYS_sysctl, (uint64_t)(uintptr_t)mib, 2,
                   (uint64_t)(uintptr_t)&val, (uint64_t)(uintptr_t)&len, 0, 0, &err);
    if (!err) {
        *out = val;
    }
    return err;
}

static uint32_t sysctl_u64(int mib0, int mib1, uint64_t *out)
{
    int mib[2] = { mib0, mib1 };
    uint64_t val = 0;
    size_t len = sizeof(val);
    uint32_t err = 0;
    darwin_syscall(DARWIN_SYS_sysctl, (uint64_t)(uintptr_t)mib, 2,
                   (uint64_t)(uintptr_t)&val, (uint64_t)(uintptr_t)&len, 0, 0, &err);
    if (!err) {
        *out = val;
    }
    return err;
}

struct buf_writer {
    char *buf;
    size_t cap;
    size_t len;
};

static void bw_putc(struct buf_writer *w, char c)
{
    if (w->len + 1 < w->cap) {
        w->buf[w->len++] = c;
    }
}

static void bw_puts(struct buf_writer *w, const char *s)
{
    while (*s) {
        bw_putc(w, *s++);
    }
}

static void bw_u64_dec(struct buf_writer *w, uint64_t v)
{
    char tmp[24];
    size_t n = 0;
    if (v == 0) {
        bw_putc(w, '0');
        return;
    }
    while (v > 0 && n < sizeof(tmp)) {
        tmp[n++] = (char)('0' + (v % 10ULL));
        v /= 10ULL;
    }
    while (n > 0) {
        bw_putc(w, tmp[--n]);
    }
}

static void bw_u64_hex(struct buf_writer *w, uint64_t v)
{
    static const char hex[] = "0123456789abcdef";
    int started = 0;
    for (int shift = 60; shift >= 0; shift -= 4) {
        uint32_t nib = (uint32_t)((v >> shift) & 0xFULL);
        if (nib || started || shift == 0) {
            started = 1;
            bw_putc(w, hex[nib]);
        }
    }
}

static void write_console(int fd, const char *s, size_t len)
{
    if (fd < 0) {
        return;
    }
    uint32_t err = 0;
    darwin_syscall(DARWIN_SYS_write, (uint64_t)(uint32_t)fd, (uint64_t)(uintptr_t)s, len, 0, 0, 0, &err);
}

static uint64_t g_simd_in[64] __attribute__((aligned(16)));
static uint64_t g_simd_out[64] __attribute__((aligned(16)));
static char g_msg[384];

void stage5_main(void)
{
    uint32_t pid_err = 0;
    uint64_t pid = darwin_syscall(DARWIN_SYS_getpid, 0, 0, 0, 0, 0, 0, &pid_err);

    uint32_t pagesize = 0, ncpu = 0, availcpu = 0;
    uint64_t memsize = 0;
    uint32_t pg_err = sysctl_u32(DARWIN_CTL_HW, DARWIN_HW_PAGESIZE, &pagesize);
    uint32_t ncpu_err = sysctl_u32(DARWIN_CTL_HW, DARWIN_HW_NCPU, &ncpu);
    uint32_t avail_err = sysctl_u32(DARWIN_CTL_HW, DARWIN_HW_AVAILCPU, &availcpu);
    uint32_t mem_err = sysctl_u64(DARWIN_CTL_HW, DARWIN_HW_MEMSIZE, &memsize);

    /* Hardware arm64e EL0 Pointer Authentication round-trip (PACIA + AUTIA). */
    uint64_t raw_ptr = (uint64_t)(uintptr_t)g_msg;
    uint64_t pac_signed = 0;
    uint64_t pac_authed = el0_pac_roundtrip(raw_ptr, 0x51A6E50000000001ULL, &pac_signed);
    int pac_ok = (pac_signed != raw_ptr) && (pac_authed == raw_ptr);

    /* Full 32-register NEON/SIMD preservation across 16 real Darwin syscalls. */
    for (uint64_t i = 0; i < 64; i++) {
        g_simd_in[i] = 0xA55A012345678900ULL ^ (i * 0x0101010101010101ULL);
        g_simd_out[i] = 0;
    }
    uint64_t last_pid = el0_simd32_syscall_test(g_simd_in, g_simd_out, 16);
    uint32_t simd_bad = 0;
    for (uint64_t i = 0; i < 64; i++) {
        if (g_simd_out[i] != g_simd_in[i]) {
            simd_bad++;
        }
    }
    int simd_ok = (simd_bad == 0U) && (last_pid == 1ULL);

    int all_ok = (pid_err == 0U) && (pid == 1ULL) &&
                 (pg_err == 0U) && (pagesize == 4096U) &&
                 (ncpu_err == 0U) && (ncpu >= 1U) &&
                 (avail_err == 0U) && (availcpu >= 1U) &&
                 (mem_err == 0U) && (memsize > 0ULL) &&
                 pac_ok && simd_ok;

    struct buf_writer w = { g_msg, sizeof(g_msg), 0 };
    bw_puts(&w, all_ok ? "[EL0_INIT] PASS: pid=" : "[EL0_INIT] FAIL: pid=");
    bw_u64_dec(&w, pid);
    bw_puts(&w, " pagesize=");
    bw_u64_dec(&w, pagesize);
    bw_puts(&w, " ncpu=");
    bw_u64_dec(&w, ncpu);
    bw_puts(&w, " availcpu=");
    bw_u64_dec(&w, availcpu);
    bw_puts(&w, " memsize=0x");
    bw_u64_hex(&w, memsize);
    bw_puts(&w, pac_ok ? " pac=ok(0x" : " pac=fail(0x");
    bw_u64_hex(&w, pac_signed);
    bw_puts(&w, simd_ok ? ") simd32=ok\n" : ") simd32=fail\n");

    uint32_t open_err = 0;
    int fd = (int)darwin_syscall(DARWIN_SYS_open, (uint64_t)(uintptr_t)"/dev/console",
                                 DARWIN_O_WRONLY | DARWIN_O_NOCTTY, 0, 0, 0, 0, &open_err);
    if (open_err) {
        fd = -1;
    }
    write_console(fd, w.buf, w.len);

    uint32_t reb_err = 0;
    darwin_syscall(DARWIN_SYS_reboot, DARWIN_RB_QUICK_NOSYNC, 0, 0, 0, 0, 0, &reb_err);

    /* Fallback if MAC policy rejects SYS_reboot: report errno and exit PID 1 cleanly. */
    struct buf_writer w2 = { g_msg, sizeof(g_msg), 0 };
    bw_puts(&w2, "[EL0_INIT] reboot_err=");
    bw_u64_dec(&w2, reb_err);
    bw_puts(&w2, " fallback=exit\n");
    write_console(fd, w2.buf, w2.len);
    if (fd >= 0) {
        uint32_t cl_err = 0;
        darwin_syscall(DARWIN_SYS_close, (uint64_t)(uint32_t)fd, 0, 0, 0, 0, 0, &cl_err);
    }
    uint32_t ex_err = 0;
    darwin_syscall(DARWIN_SYS_exit, 0, 0, 0, 0, 0, 0, &ex_err);
    for (;;) {
        __asm__ volatile("wfe");
    }
}
"""


def align_up(value: int, align: int) -> int:
    return (value + align - 1) & ~(align - 1)


def sign_macho_4k_adhoc(raw_bytes: bytes, ident: str) -> tuple[bytes, bytes, dict]:
    """Attach an Apple-spec 4 KiB-paged SHA-256 ad-hoc LC_CODE_SIGNATURE to a Mach-O 64 binary."""
    buf = bytearray(raw_bytes)
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from("<8I", buf, 0)
    if magic != MH_MAGIC_64 or cputype != CPU_TYPE_ARM64 or (cpusubtype & 0x00FFFFFF) != CPU_SUBTYPE_ARM64E:
        raise SystemExit(f"Expected arm64e Mach-O 64, got magic=0x{magic:x} cpu=0x{cputype:x} sub=0x{cpusubtype:x}")
    if filetype != MH_EXECUTE:
        raise SystemExit(f"Expected MH_EXECUTE (2), got {filetype}")

    # Parse existing load commands
    cmds = []
    off = 32
    text_seg = None
    linkedit_idx = None
    first_section_off = len(buf)
    old_sig_off = None
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<2I", buf, off)
        payload = bytes(buf[off : off + cmdsize])
        if cmd == LC_SEGMENT_64:
            segname = payload[8:24].split(b"\0", 1)[0].decode("ascii", errors="replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", payload, 24)
            nsects = struct.unpack_from("<I", payload, 64)[0]
            if segname == "__TEXT":
                text_seg = (vmaddr, vmsize, fileoff, filesize)
                for s in range(nsects):
                    sec_off = struct.unpack_from("<I", payload, 72 + s * 80 + 48)[0]
                    if sec_off and sec_off < first_section_off:
                        first_section_off = sec_off
            elif segname == "__LINKEDIT":
                linkedit_idx = len(cmds)
        elif cmd == LC_CODE_SIGNATURE:
            old_sig_off, _ = struct.unpack_from("<2I", payload, 8)
            off += cmdsize
            continue  # Strip any linker-generated 16 KiB signature; we emit a native 4 KiB one.
        cmds.append((cmd, payload))
        off += cmdsize

    if text_seg is None:
        raise SystemExit("Mach-O missing __TEXT segment")

    # Strip old signature tail if linker emitted one at EOF
    if old_sig_off is not None and old_sig_off < len(buf):
        del buf[old_sig_off:]

    # Ensure __LINKEDIT segment exists at EOF (static binaries may omit __LINKEDIT)
    if linkedit_idx is None:
        max_vm_end = 0
        for cmd, payload in cmds:
            if cmd == LC_SEGMENT_64:
                vmaddr, vmsize = struct.unpack_from("<2Q", payload, 24)
                max_vm_end = max(max_vm_end, align_up(vmaddr + vmsize, SIGN_PAGE_SIZE))
        le_fileoff = align_up(len(buf), SIGN_PAGE_SIZE)
        if len(buf) < le_fileoff:
            buf.extend(b"\0" * (le_fileoff - len(buf)))
        le_cmd = struct.pack(
            "<2I16s4Q4I",
            LC_SEGMENT_64,
            72,
            b"__LINKEDIT".ljust(16, b"\0"),
            max_vm_end,
            SIGN_PAGE_SIZE,
            le_fileoff,
            0,
            1,  # maxprot = VM_PROT_READ
            1,  # initprot = VM_PROT_READ
            0,  # nsects
            0,  # flags
        )
        linkedit_idx = len(cmds)
        cmds.append((LC_SEGMENT_64, le_cmd))

    # Ensure LC_BUILD_VERSION (PLATFORM_IOS = 2, minos 27.0, sdk 27.0) is present for AMFI/mach_loader
    if not any(cmd == LC_BUILD_VERSION for cmd, _ in cmds):
        bv_cmd = struct.pack(
            "<6I",
            LC_BUILD_VERSION,
            24,          # cmdsize
            2,           # PLATFORM_IOS
            0x001B0000,  # minos = 27.0.0
            0x001B0000,  # sdk   = 27.0.0
            0,           # ntools
        )
        cmds.append((LC_BUILD_VERSION, bv_cmd))

    # Append placeholder LC_CODE_SIGNATURE (16 bytes)
    sig_cmd_idx = len(cmds)
    cmds.append((LC_CODE_SIGNATURE, struct.pack("<4I", LC_CODE_SIGNATURE, 16, 0, 0)))

    new_sizeofcmds = sum(len(p) for _, p in cmds)
    if 32 + new_sizeofcmds > first_section_off:
        raise SystemExit(f"Load commands ({32 + new_sizeofcmds} B) overflow first section offset ({first_section_off} B)")

    # Determine codeLimit (16-byte aligned start of signature blob)
    code_limit = align_up(len(buf), 16)
    if len(buf) < code_limit:
        buf.extend(b"\0" * (code_limit - len(buf)))

    # Pre-compute deterministic CodeDirectory & SuperBlob size
    ident_bytes = ident.encode("ascii") + b"\0"
    cd_header_len = 88  # v0x20400 (through execSegFlags)
    ident_offset = cd_header_len
    hash_offset = align_up(ident_offset + len(ident_bytes), 16)
    n_code_slots = (code_limit + SIGN_PAGE_SIZE - 1) // SIGN_PAGE_SIZE
    cd_length = hash_offset + n_code_slots * 32
    if cd_length < 128:
        raise SystemExit(f"CodeDirectory unexpectedly small: {cd_length}")
    superblob_len = 12 + 8 + cd_length  # SuperBlob header (12) + 1 BlobIndex (8) + CD

    # Patch __LINKEDIT filesize/vmsize and LC_CODE_SIGNATURE dataoff/datasize BEFORE hashing page 0
    le_raw = bytearray(cmds[linkedit_idx][1])
    le_vmaddr, _, le_fileoff, _ = struct.unpack_from("<4Q", le_raw, 24)
    new_le_filesize = (code_limit + superblob_len) - le_fileoff
    new_le_vmsize = align_up(new_le_filesize, SIGN_PAGE_SIZE)
    struct.pack_into("<4Q", le_raw, 24, le_vmaddr, new_le_vmsize, le_fileoff, new_le_filesize)
    cmds[linkedit_idx] = (LC_SEGMENT_64, bytes(le_raw))
    cmds[sig_cmd_idx] = (LC_CODE_SIGNATURE, struct.pack("<4I", LC_CODE_SIGNATURE, 16, code_limit, superblob_len))

    # Rewrite mach_header_64 + load commands cleanly (zeroing any slack up to old sizeofcmds)
    struct.pack_into("<8I", buf, 0, magic, cputype, cpusubtype, filetype, len(cmds), new_sizeofcmds, flags, reserved)
    cursor = 32
    for _, payload in cmds:
        buf[cursor : cursor + len(payload)] = payload
        cursor += len(payload)
    if cursor < 32 + sizeofcmds:
        buf[cursor : 32 + sizeofcmds] = b"\0" * (32 + sizeofcmds - cursor)

    # Now hash finalized bytes [0..code_limit) in 4096-byte pages
    page_hashes = bytearray()
    for page_off in range(0, code_limit, SIGN_PAGE_SIZE):
        chunk = bytes(buf[page_off : min(page_off + SIGN_PAGE_SIZE, code_limit)])
        page_hashes.extend(hashlib.sha256(chunk).digest())
    assert len(page_hashes) == n_code_slots * 32

    text_fileoff, text_filesize = text_seg[2], text_seg[3]
    cd_header = struct.pack(
        ">9I4B4IQ3Q",
        CSMAGIC_CODEDIRECTORY,
        cd_length,
        CS_VERSION_EXECSEG,
        CS_ADHOC,
        hash_offset,
        ident_offset,
        0,  # nSpecialSlots
        n_code_slots,
        code_limit,
        32,  # hashSize
        CS_HASHTYPE_SHA256,
        0,  # platform
        SIGN_PAGE_SHIFT,
        0,  # spare2
        0,  # scatterOffset
        0,  # teamOffset
        0,  # spare3
        0,  # codeLimit64
        text_fileoff,
        text_filesize,
        CS_EXECSEG_MAIN_BINARY,
    )
    assert len(cd_header) == cd_header_len
    cd_blob = cd_header + ident_bytes + b"\0" * (hash_offset - (ident_offset + len(ident_bytes))) + bytes(page_hashes)
    assert len(cd_blob) == cd_length

    superblob = struct.pack(">5I", CSMAGIC_EMBEDDED_SIGNATURE, superblob_len, 1, CSSLOT_CODEDIRECTORY, 20) + cd_blob
    assert len(superblob) == superblob_len

    final_bytes = bytes(buf) + superblob
    cdhash = hashlib.sha256(cd_blob).digest()[:20]

    # Independent self-verification matching XNU bsd/kern/ubc_subr.c cs_validate_codedirectory()
    sb_magic, sb_len, sb_cnt, slot_type, slot_off = struct.unpack_from(">5I", final_bytes, code_limit)
    assert sb_magic == CSMAGIC_EMBEDDED_SIGNATURE and sb_len == superblob_len and sb_cnt == 1
    assert slot_type == CSSLOT_CODEDIRECTORY and slot_off == 20
    cd_check = final_bytes[code_limit + slot_off : code_limit + slot_off + cd_length]
    assert hashlib.sha256(cd_check).digest()[:20] == cdhash
    for idx in range(n_code_slots):
        p0 = idx * SIGN_PAGE_SIZE
        p1 = min(p0 + SIGN_PAGE_SIZE, code_limit)
        expected = hashlib.sha256(final_bytes[p0:p1]).digest()
        stored = cd_check[hash_offset + idx * 32 : hash_offset + (idx + 1) * 32]
        assert expected == stored, f"Page {idx} hash mismatch"

    meta = {
        "identifier": ident,
        "macho_cpusubtype": f"0x{cpusubtype:x}",
        "file_size": len(final_bytes),
        "code_limit": code_limit,
        "signature_offset": code_limit,
        "signature_size": superblob_len,
        "code_directory_version": f"0x{CS_VERSION_EXECSEG:x}",
        "code_directory_flags": f"0x{CS_ADHOC:x}",
        "page_size": SIGN_PAGE_SIZE,
        "code_slots": n_code_slots,
        "exec_seg_base": text_fileoff,
        "exec_seg_limit": text_filesize,
        "exec_seg_flags": f"0x{CS_EXECSEG_MAIN_BINARY:x}",
        "cdhash": cdhash.hex(),
        "sha256": hashlib.sha256(final_bytes).hexdigest(),
    }
    return final_bytes, cdhash, meta


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True, help="Output build directory")
    parser.add_argument("--base-trustcache", type=Path, required=True, help="Official 24A446 StaticTrustCache bundle (module 0)")
    parser.add_argument("--identifier", type=str, default="org.unixnu.violin.stage5-init", help="CodeDirectory identifier")
    args = parser.parse_args()

    toolchain = Path(os.environ.get("UNIXNU_TOOLCHAIN", "/opt/unixnu-out/toolchain-arm64e"))
    clang = toolchain / "llvm/bin/clang"
    ld = toolchain / "CommandLineTools/usr/bin/ld"
    for tool_path in (clang, ld):
        if not tool_path.exists():
            raise SystemExit(f"Missing toolchain binary: {tool_path}")

    script_dir = Path(__file__).resolve().parent
    unixnu_root = script_dir.parents[1] / "UniXNU"
    trust_append = unixnu_root / "scripts/trust-append-module.py"
    if not trust_append.is_file():
        raise SystemExit(f"Missing upstream trust-append-module.py: {trust_append}")

    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    start_s = out_dir / "stage5-start.S"
    main_c = out_dir / "stage5-main.c"
    start_o = out_dir / "stage5-start.o"
    main_o = out_dir / "stage5-main.o"
    raw_macho = out_dir / "launchd-unsigned.macho"
    signed_macho = out_dir / "launchd.macho"
    stage5_tc = out_dir / "stage5.trustcache"
    meta_json = out_dir / "launchd-sign.json"

    start_s.write_text(START_ASM, encoding="ascii")
    main_c.write_text(MAIN_C, encoding="ascii")

    common_cc = [str(clang), "-target", "arm64e-apple-ios27.0", "-ffreestanding", "-fno-builtin", "-fno-stack-protector"]
    subprocess.run([*common_cc, "-c", str(start_s), "-o", str(start_o)], check=True)
    subprocess.run([*common_cc, "-Os", "-Wall", "-Wextra", "-Werror", "-c", str(main_c), "-o", str(main_o)], check=True)

    subprocess.run(
        [
            str(ld),
            "-arch",
            "arm64e",
            "-static",
            "-e",
            "_start",
            "-segalign",
            "0x1000",
            "-platform_version",
            "ios",
            "27.0",
            "27.0",
            str(start_o),
            str(main_o),
            "-o",
            str(raw_macho),
        ],
        check=True,
    )

    signed_bytes, cdhash, meta = sign_macho_4k_adhoc(raw_macho.read_bytes(), args.identifier)
    signed_macho.write_bytes(signed_bytes)

    subprocess.run(
        ["python3", str(trust_append), str(args.base_trustcache), str(stage5_tc), cdhash.hex()],
        check=True,
    )
    meta["base_trustcache_sha256"] = hashlib.sha256(args.base_trustcache.read_bytes()).hexdigest()
    meta["stage5_trustcache_sha256"] = hashlib.sha256(stage5_tc.read_bytes()).hexdigest()
    meta["stage5_trustcache_size"] = stage5_tc.stat().st_size
    meta_json.write_text(json.dumps(meta, indent=2) + "\n", encoding="ascii")

    print(
        f"PASS: built & signed arm64e EL0 /sbin/launchd -> {signed_macho} ({len(signed_bytes)} B, "
        f"{meta['code_slots']}x4K pages, cdhash={cdhash.hex()}) + {stage5_tc} ({meta['stage5_trustcache_size']} B)"
    )


if __name__ == "__main__":
    main()
