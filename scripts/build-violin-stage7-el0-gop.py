#!/usr/bin/env python3
"""Build and sign Stage-7B static arm64e EL0 /sbin/launchd (Stage-5 + NativeGOPPresenter client).

Compiles a freestanding arm64e-apple-ios27.0 Mach-O static executable (zero libc/dyld),
runs all Stage-5 EL0 checks (pid/pagesize/ncpu/availcpu/memsize/PAC/SIMD32), then uses
raw mach_msg2_trap (-47) with MACH64_SEND_KOBJECT_CALL to drive NativeGOPPresenter:
  1. host_get_io_main (205)
  2. io_service_get_matching_service_bin (2880) -> NativeGOPPresenter
  3. io_service_open_extended (2862) -> NativeGOPClient
  4. io_connect_method (2865, NGP_METHOD_MODE=0) -> NGPMode
  5. SYS_mmap (197) + 4-quadrant BGRX8888 test pattern render
  6. io_connect_method (2865, NGP_METHOD_PRESENT=1) + CNTPCT_EL0 transfer timing
  7. io_connect_map_memory_into_task (2863, type=0, kIOMapAnywhere) -> scanout readback verify
  8. 3-second visual hold on 3200x2136 live panel before clean SYS_reboot

SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import argparse
import hashlib
import json
import os
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
    bl      _stage7_main
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

/* Freestanding memset/memcpy so compiler-generated struct copies resolve without libc. */
void *memset(void *dst, int c, size_t n)
{
    uint8_t *p = (uint8_t *)dst;
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)c;
    }
    return dst;
}

void *memcpy(void *dst, const void *src, size_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dst;
}

enum {
    DARWIN_SYS_exit   = 1,
    DARWIN_SYS_write  = 4,
    DARWIN_SYS_open   = 5,
    DARWIN_SYS_close  = 6,
    DARWIN_SYS_getpid = 20,
    DARWIN_SYS_reboot = 55,
    DARWIN_SYS_munmap = 73,
    DARWIN_SYS_mmap   = 197,
    DARWIN_SYS_sysctl = 202,
};

enum {
    DARWIN_O_WRONLY        = 0x00001,
    DARWIN_O_NOCTTY        = 0x20000,
    DARWIN_PROT_READ       = 0x1,
    DARWIN_PROT_WRITE      = 0x2,
    DARWIN_MAP_PRIVATE     = 0x0002,
    DARWIN_MAP_ANON        = 0x1000,
    DARWIN_CTL_HW          = 6,
    DARWIN_HW_NCPU         = 3,
    DARWIN_HW_PAGESIZE     = 7,
    DARWIN_HW_MEMSIZE      = 24,
    DARWIN_HW_AVAILCPU     = 25,
    DARWIN_RB_QUICK_NOSYNC = 0x404,
};

/* Mach trap numbers (invoked via negative x16 with svc #0x80). */
enum {
    MACH_TRAP_TASK_SELF          = -28,
    MACH_TRAP_HOST_SELF          = -29,
    MACH_TRAP_MSG2               = -47,
    MACH_TRAP_SPECIAL_REPLY_PORT = -50,
};

/* Mach IPC constants (XNU 12377 / iOS 27). */
enum {
    MACH_MSG_TYPE_COPY_SEND      = 19U,
    MACH_MSG_TYPE_MAKE_SEND_ONCE = 21U,
    MACH_MSGH_BITS_COMPLEX       = 0x80000000U,
    MACH_MSG_PORT_DESCRIPTOR     = 0U,
    MACH_MSG_OOL_DESCRIPTOR      = 1U,
    MACH_MSG_PHYSICAL_COPY       = 0U,
    KIOMAP_ANYWHERE              = 0x00000001U,
    KIORETURN_NOT_FOUND          = 0xE00002F0U,
};

static const uint64_t MACH64_SEND_MSG          = 0x0000000000000001ULL;
static const uint64_t MACH64_RCV_MSG           = 0x0000000000000002ULL;
static const uint64_t MACH64_SEND_KOBJECT_CALL = 0x0000000200000000ULL;

/* NativeGOPWire.h ABI (must match source/UniXNU/drivers/GopFramebuffer/NativeGOPWire.h). */
enum {
    NGP_BGRX8888       = 1U,
    NGP_VERSION        = 1U,
    NGP_METHOD_MODE    = 0U,
    NGP_METHOD_PRESENT = 1U,
};

struct NGPMode {
    uint32_t version;
    uint32_t format;
    uint64_t width;
    uint64_t height;
    uint64_t stride;
    uint64_t bytes;
};

struct NGPPresent {
    uint64_t address;
    uint64_t bytes;
    uint32_t width;
    uint32_t height;
    uint32_t stride;
    uint32_t format;
};

struct NGPTransfer {
    uint64_t sequence;
    uint64_t bytes;
};

_Static_assert(sizeof(struct NGPMode) == 40, "NGPMode size");
_Static_assert(sizeof(struct NGPPresent) == 32, "NGPPresent size");
_Static_assert(sizeof(struct NGPTransfer) == 16, "NGPTransfer size");

/* MIG wire structures (#pragma pack(4), matching XNU generated device_server.h / mach_host_server.h). */
#pragma pack(push, 4)

struct mach_msg_hdr {
    uint32_t msgh_bits;
    uint32_t msgh_size;
    uint32_t msgh_remote_port;
    uint32_t msgh_local_port;
    uint32_t msgh_voucher_port;
    int32_t  msgh_id;
};

struct mach_msg_body {
    uint32_t msgh_descriptor_count;
};

struct mach_msg_port_desc {
    uint32_t name;
    uint32_t pad1;
    uint16_t pad2;
    uint8_t  disposition;
    uint8_t  type;
};

struct mach_msg_ool_desc64 {
    uint64_t address;
    uint8_t  deallocate;
    uint8_t  copy;
    uint8_t  pad1;
    uint8_t  type;
    uint32_t size;
};

struct ndr_record {
    uint8_t bytes[8];
};

struct mig_reply_error {
    struct mach_msg_hdr Head;
    struct ndr_record   NDR;
    uint32_t            RetCode;
};

/* 205: host_get_io_main */
struct req_host_get_io_main {
    struct mach_msg_hdr Head;
};

struct rep_host_get_io_main {
    struct mach_msg_hdr       Head;
    struct mach_msg_body      msgh_body;
    struct mach_msg_port_desc io_main;
    uint8_t                   trailer[64];
};

/* 2880: io_service_get_matching_service_bin */
struct req_matching_bin {
    struct mach_msg_hdr Head;
    struct ndr_record   NDR;
    uint32_t            matchingCnt;
    char                matching[128];
};

struct rep_matching_bin {
    struct mach_msg_hdr       Head;
    struct mach_msg_body      msgh_body;
    struct mach_msg_port_desc service;
    uint8_t                   trailer[64];
};

/* 2862: io_service_open_extended */
struct req_open_ext {
    struct mach_msg_hdr        Head;
    struct mach_msg_body       msgh_body;
    struct mach_msg_port_desc  owningTask;
    struct mach_msg_ool_desc64 properties;
    struct ndr_record          NDR;
    uint32_t                   connect_type;
    struct ndr_record          ndr;
    uint32_t                   propertiesCnt;
};

struct rep_open_ext {
    struct mach_msg_hdr       Head;
    struct mach_msg_body      msgh_body;
    struct mach_msg_port_desc connection;
    struct ndr_record         NDR;
    uint32_t                  result;
    uint8_t                   trailer[64];
};

/* 2865: io_connect_method (scalar_inputCnt == 0, variable inband_input) */
struct req_connect_method_mode {
    struct mach_msg_hdr Head;
    struct ndr_record   NDR;
    uint32_t            selector;
    uint32_t            scalar_inputCnt;
    uint32_t            inband_inputCnt;
    uint64_t            ool_input;
    uint64_t            ool_input_size;
    uint32_t            inband_outputCnt;
    uint32_t            scalar_outputCnt;
    uint64_t            ool_output;
    uint64_t            ool_output_size;
};

struct req_connect_method_present {
    struct mach_msg_hdr Head;
    struct ndr_record   NDR;
    uint32_t            selector;
    uint32_t            scalar_inputCnt;
    uint32_t            inband_inputCnt;
    struct NGPPresent   inband_input;
    uint64_t            ool_input;
    uint64_t            ool_input_size;
    uint32_t            inband_outputCnt;
    uint32_t            scalar_outputCnt;
    uint64_t            ool_output;
    uint64_t            ool_output_size;
};

struct rep_connect_method_buf {
    struct mach_msg_hdr Head;
    struct ndr_record   NDR;
    uint32_t            RetCode;
    uint32_t            inband_outputCnt;
    uint8_t             payload[256];
};

/* 2863: io_connect_map_memory_into_task */
struct req_map_memory {
    struct mach_msg_hdr       Head;
    struct mach_msg_body      msgh_body;
    struct mach_msg_port_desc into_task;
    struct ndr_record         NDR;
    uint32_t                  memory_type;
    uint64_t                  address;
    uint64_t                  size;
    uint32_t                  flags;
};

struct rep_map_memory {
    struct mach_msg_hdr Head;
    struct ndr_record   NDR;
    uint32_t            RetCode;
    uint64_t            address;
    uint64_t            size;
    uint8_t             trailer[64];
};

#pragma pack(pop)

_Static_assert(sizeof(struct mach_msg_hdr) == 24, "mach_msg_hdr");
_Static_assert(sizeof(struct mach_msg_port_desc) == 12, "port_desc");
_Static_assert(sizeof(struct mach_msg_ool_desc64) == 16, "ool_desc64");
_Static_assert(sizeof(struct req_open_ext) == 80, "req_open_ext");
_Static_assert(sizeof(struct req_connect_method_mode) == 84, "req_mode");
_Static_assert(sizeof(struct req_connect_method_present) == 116, "req_present");
_Static_assert(sizeof(struct req_map_memory) == 72, "req_map_memory");

static const struct ndr_record kNDR = { { 0, 0, 0, 0, 1, 0, 0, 0 } };

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

static uint32_t mach_trap0(int64_t trap_num)
{
    register uint64_t x0 __asm__("x0") = 0;
    register uint64_t x16 __asm__("x16") = (uint64_t)trap_num;
    __asm__ volatile(
        "svc #0x80"
        : "+r"(x0)
        : "r"(x16)
        : "memory", "cc");
    return (uint32_t)x0;
}

static uint32_t mach_msg2_rpc(void *buf, uint32_t send_size, uint32_t rcv_size,
                              uint32_t msgh_bits, uint32_t remote_port,
                              uint32_t reply_port, int32_t msgh_id, uint32_t desc_count)
{
    struct mach_msg_hdr *hdr = (struct mach_msg_hdr *)buf;
    hdr->msgh_bits = msgh_bits;
    hdr->msgh_size = send_size;
    hdr->msgh_remote_port = remote_port;
    hdr->msgh_local_port = reply_port;
    hdr->msgh_voucher_port = 0U;
    hdr->msgh_id = msgh_id;

    register uint64_t x0 __asm__("x0") = (uint64_t)(uintptr_t)buf;
    register uint64_t x1 __asm__("x1") = MACH64_SEND_MSG | MACH64_RCV_MSG | MACH64_SEND_KOBJECT_CALL;
    register uint64_t x2 __asm__("x2") = ((uint64_t)send_size << 32) | (uint64_t)msgh_bits;
    register uint64_t x3 __asm__("x3") = ((uint64_t)reply_port << 32) | (uint64_t)remote_port;
    register uint64_t x4 __asm__("x4") = ((uint64_t)(uint32_t)msgh_id << 32);
    register uint64_t x5 __asm__("x5") = ((uint64_t)reply_port << 32) | (uint64_t)desc_count;
    register uint64_t x6 __asm__("x6") = (uint64_t)rcv_size;
    register uint64_t x7 __asm__("x7") = 0ULL;
    register uint64_t x16 __asm__("x16") = (uint64_t)(int64_t)MACH_TRAP_MSG2;

    __asm__ volatile(
        "svc #0x80"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6), "r"(x7), "r"(x16)
        : "memory", "cc");
    return (uint32_t)x0;
}

static inline uint64_t read_cntpct(void)
{
    uint64_t v;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(v) :: "memory");
    return v;
}

static inline uint64_t read_cntfrq(void)
{
    uint64_t v;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(v) :: "memory");
    return v;
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

/* Deterministic 4-quadrant BGRX8888 test pattern (matches scanout readback identically). */
static uint32_t pattern_pixel(uint32_t x, uint32_t y, uint32_t w, uint32_t h)
{
    /* 8 px solid white outer frame */
    if (x < 8U || y < 8U || x + 8U >= w || y + 8U >= h) {
        return 0xFFFFFFFFU;
    }
    uint32_t cx = w >> 1;
    uint32_t cy = h >> 1;
    /* Center bullseye: 80x80 yellow inside 160x160 magenta */
    uint32_t dx = (x >= cx) ? (x - cx) : (cx - x);
    uint32_t dy = (y >= cy) ? (y - cy) : (cy - y);
    if (dx < 40U && dy < 40U) {
        return 0xFFFFFF00U; /* Yellow */
    }
    if (dx < 80U && dy < 80U) {
        return 0xFFFF00FFU; /* Magenta */
    }
    /* 6 px cyan crosshair */
    if (dx < 3U || dy < 3U) {
        return 0xFF00FFFFU; /* Cyan */
    }
    /* 4 quadrants */
    if (y < cy) {
        return (x < cx) ? 0xFFFF0000U : 0xFF00FF00U; /* TL Red, TR Green */
    }
    if (x < cx) {
        return 0xFF0000FFU; /* BL Blue */
    }
    /* BR 64x64 white/dark-gray checkerboard */
    return (((x >> 6) + (y >> 6)) & 1U) ? 0xFF202020U : 0xFFFFFFFFU;
}

static uint64_t g_simd_in[64] __attribute__((aligned(16)));
static uint64_t g_simd_out[64] __attribute__((aligned(16)));
static char g_msg[512];
static uint8_t g_ipc_buf[1024] __attribute__((aligned(16)));

static void log_gop_fail(int fd, const char *step, uint32_t mr, uint32_t kr, uint32_t extra)
{
    struct buf_writer w = { g_msg, sizeof(g_msg), 0 };
    bw_puts(&w, "[EL0_GOP] FAIL: step=");
    bw_puts(&w, step);
    bw_puts(&w, " mr=0x");
    bw_u64_hex(&w, mr);
    bw_puts(&w, " kr=0x");
    bw_u64_hex(&w, kr);
    bw_puts(&w, " extra=0x");
    bw_u64_hex(&w, extra);
    bw_puts(&w, "\n");
    write_console(fd, w.buf, w.len);
}

static void run_gop_test(int fd)
{
    uint32_t host_self = mach_trap0(MACH_TRAP_HOST_SELF);
    uint32_t task_self = mach_trap0(MACH_TRAP_TASK_SELF);
    uint32_t reply_port = mach_trap0(MACH_TRAP_SPECIAL_REPLY_PORT);
    if (!host_self || !task_self || !reply_port) {
        log_gop_fail(fd, "ports", host_self, task_self, reply_port);
        return;
    }

    const uint32_t bits_simple = MACH_MSG_TYPE_COPY_SEND | (MACH_MSG_TYPE_MAKE_SEND_ONCE << 8);
    const uint32_t bits_complex = bits_simple | MACH_MSGH_BITS_COMPLEX;

    /* 1. host_get_io_main (205) */
    memset(g_ipc_buf, 0, sizeof(g_ipc_buf));
    uint32_t mr = mach_msg2_rpc(g_ipc_buf, (uint32_t)sizeof(struct req_host_get_io_main),
                                (uint32_t)sizeof(struct rep_host_get_io_main),
                                bits_simple, host_self, reply_port, 205, 0U);
    if (mr != 0U) {
        log_gop_fail(fd, "host_get_io_main", mr, 0U, 0U);
        return;
    }
    struct rep_host_get_io_main *rep_main = (struct rep_host_get_io_main *)g_ipc_buf;
    if ((rep_main->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) == 0U) {
        struct mig_reply_error *err = (struct mig_reply_error *)g_ipc_buf;
        log_gop_fail(fd, "host_get_io_main_mig", 0U, err->RetCode, (uint32_t)rep_main->Head.msgh_id);
        return;
    }
    uint32_t io_main = rep_main->io_main.name;
    if (!io_main) {
        log_gop_fail(fd, "io_main_null", 0U, 0U, 0U);
        return;
    }

    /* 2. io_service_get_matching_service_bin (2880) */
    static const char kMatchXml[] =
        "<dict><key>IOProviderClass</key><string>NativeGOPPresenter</string></dict> ";
    /* sizeof(kMatchXml) == 76 (75 chars + NUL, exact 4-byte multiple). */
    const uint32_t match_len = (uint32_t)sizeof(kMatchXml);
    const uint32_t match_send_sz = 24U + 8U + 4U + ((match_len + 3U) & ~3U);
    memset(g_ipc_buf, 0, sizeof(g_ipc_buf));
    struct req_matching_bin *req_m = (struct req_matching_bin *)g_ipc_buf;
    req_m->NDR = kNDR;
    req_m->matchingCnt = match_len;
    memcpy(req_m->matching, kMatchXml, match_len);

    mr = mach_msg2_rpc(g_ipc_buf, match_send_sz, (uint32_t)sizeof(struct rep_matching_bin),
                       bits_simple, io_main, reply_port, 2880, 0U);
    if (mr != 0U) {
        log_gop_fail(fd, "matching_bin", mr, 0U, io_main);
        return;
    }
    struct rep_matching_bin *rep_m = (struct rep_matching_bin *)g_ipc_buf;
    if ((rep_m->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) == 0U) {
        struct mig_reply_error *err = (struct mig_reply_error *)g_ipc_buf;
        if (err->RetCode == KIORETURN_NOT_FOUND) {
            static const char kSkip[] = "[EL0_GOP] SKIP: NativeGOPPresenter not registered\n";
            write_console(fd, kSkip, sizeof(kSkip) - 1U);
            return;
        }
        log_gop_fail(fd, "matching_bin_mig", 0U, err->RetCode, (uint32_t)rep_m->Head.msgh_id);
        return;
    }
    uint32_t service = rep_m->service.name;
    if (!service) {
        log_gop_fail(fd, "service_null", 0U, 0U, 0U);
        return;
    }

    /* 3. io_service_open_extended (2862) */
    memset(g_ipc_buf, 0, sizeof(g_ipc_buf));
    struct req_open_ext *req_o = (struct req_open_ext *)g_ipc_buf;
    req_o->msgh_body.msgh_descriptor_count = 2U;
    req_o->owningTask.name = task_self;
    req_o->owningTask.disposition = MACH_MSG_TYPE_COPY_SEND;
    req_o->owningTask.type = MACH_MSG_PORT_DESCRIPTOR;
    req_o->properties.address = 0ULL;
    req_o->properties.deallocate = 0U;
    req_o->properties.copy = MACH_MSG_PHYSICAL_COPY;
    req_o->properties.type = MACH_MSG_OOL_DESCRIPTOR;
    req_o->properties.size = 0U;
    req_o->NDR = kNDR;
    req_o->connect_type = 0U;
    req_o->ndr = kNDR;
    req_o->propertiesCnt = 0U;

    mr = mach_msg2_rpc(g_ipc_buf, (uint32_t)sizeof(struct req_open_ext),
                       (uint32_t)sizeof(struct rep_open_ext),
                       bits_complex, service, reply_port, 2862, 2U);
    if (mr != 0U) {
        log_gop_fail(fd, "open_ext", mr, 0U, service);
        return;
    }
    struct rep_open_ext *rep_o = (struct rep_open_ext *)g_ipc_buf;
    if ((rep_o->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) == 0U) {
        struct mig_reply_error *err = (struct mig_reply_error *)g_ipc_buf;
        log_gop_fail(fd, "open_ext_mig", 0U, err->RetCode, (uint32_t)rep_o->Head.msgh_id);
        return;
    }
    if (rep_o->result != 0U || rep_o->connection.name == 0U) {
        log_gop_fail(fd, "open_ext_res", 0U, rep_o->result, rep_o->connection.name);
        return;
    }
    uint32_t connect = rep_o->connection.name;

    /* 4. io_connect_method (2865, NGP_METHOD_MODE = 0) */
    memset(g_ipc_buf, 0, sizeof(g_ipc_buf));
    struct req_connect_method_mode *req_mode = (struct req_connect_method_mode *)g_ipc_buf;
    req_mode->NDR = kNDR;
    req_mode->selector = NGP_METHOD_MODE;
    req_mode->scalar_inputCnt = 0U;
    req_mode->inband_inputCnt = 0U;
    req_mode->inband_outputCnt = (uint32_t)sizeof(struct NGPMode);
    req_mode->scalar_outputCnt = 0U;

    mr = mach_msg2_rpc(g_ipc_buf, (uint32_t)sizeof(struct req_connect_method_mode),
                       (uint32_t)sizeof(struct rep_connect_method_buf),
                       bits_simple, connect, reply_port, 2865, 0U);
    if (mr != 0U) {
        log_gop_fail(fd, "method_mode", mr, 0U, connect);
        return;
    }
    struct rep_connect_method_buf *rep_mode = (struct rep_connect_method_buf *)g_ipc_buf;
    if (rep_mode->RetCode != 0U || rep_mode->inband_outputCnt != sizeof(struct NGPMode)) {
        log_gop_fail(fd, "method_mode_ret", 0U, rep_mode->RetCode, rep_mode->inband_outputCnt);
        return;
    }
    struct NGPMode mode;
    memcpy(&mode, rep_mode->payload, sizeof(mode));
    if (mode.version != NGP_VERSION || mode.format != NGP_BGRX8888 ||
        mode.width == 0ULL || mode.height == 0ULL ||
        mode.stride < mode.width * 4ULL || mode.bytes != mode.stride * mode.height) {
        log_gop_fail(fd, "mode_invalid", mode.version, mode.format, (uint32_t)mode.width);
        return;
    }

    /* 5. Allocate userland staging framebuffer via SYS_mmap and render 4-quadrant test pattern */
    uint32_t mmap_err = 0U;
    uint64_t fb_user_va = darwin_syscall(
        DARWIN_SYS_mmap,
        0ULL,
        mode.bytes,
        (uint64_t)(DARWIN_PROT_READ | DARWIN_PROT_WRITE),
        (uint64_t)(DARWIN_MAP_PRIVATE | DARWIN_MAP_ANON),
        (uint64_t)(int64_t)-1,
        0ULL,
        &mmap_err);
    if (mmap_err != 0U || fb_user_va == 0ULL || fb_user_va == ~0ULL) {
        log_gop_fail(fd, "mmap", mmap_err, (uint32_t)(fb_user_va >> 32), (uint32_t)fb_user_va);
        return;
    }

    uint32_t w32 = (uint32_t)mode.width;
    uint32_t h32 = (uint32_t)mode.height;
    uint32_t stride_px = (uint32_t)(mode.stride >> 2);
    uint32_t *dst_px = (uint32_t *)(uintptr_t)fb_user_va;
    for (uint32_t y = 0; y < h32; y++) {
        uint32_t *row = dst_px + ((size_t)y * (size_t)stride_px);
        for (uint32_t x = 0; x < w32; x++) {
            row[x] = pattern_pixel(x, y, w32, h32);
        }
    }

    /* 6. io_connect_method (2865, NGP_METHOD_PRESENT = 1) with CNTPCT_EL0 timing */
    memset(g_ipc_buf, 0, sizeof(g_ipc_buf));
    struct req_connect_method_present *req_p = (struct req_connect_method_present *)g_ipc_buf;
    req_p->NDR = kNDR;
    req_p->selector = NGP_METHOD_PRESENT;
    req_p->scalar_inputCnt = 0U;
    req_p->inband_inputCnt = (uint32_t)sizeof(struct NGPPresent);
    req_p->inband_input.address = fb_user_va;
    req_p->inband_input.bytes = mode.bytes;
    req_p->inband_input.width = w32;
    req_p->inband_input.height = h32;
    req_p->inband_input.stride = (uint32_t)mode.stride;
    req_p->inband_input.format = mode.format;
    req_p->inband_outputCnt = (uint32_t)sizeof(struct NGPTransfer);
    req_p->scalar_outputCnt = 0U;

    uint64_t freq = read_cntfrq();
    uint64_t t0 = read_cntpct();
    mr = mach_msg2_rpc(g_ipc_buf, (uint32_t)sizeof(struct req_connect_method_present),
                       (uint32_t)sizeof(struct rep_connect_method_buf),
                       bits_simple, connect, reply_port, 2865, 0U);
    uint64_t t1 = read_cntpct();
    if (mr != 0U) {
        log_gop_fail(fd, "method_present", mr, 0U, connect);
        return;
    }
    struct rep_connect_method_buf *rep_p = (struct rep_connect_method_buf *)g_ipc_buf;
    if (rep_p->RetCode != 0U || rep_p->inband_outputCnt != sizeof(struct NGPTransfer)) {
        log_gop_fail(fd, "method_present_ret", 0U, rep_p->RetCode, rep_p->inband_outputCnt);
        return;
    }
    struct NGPTransfer xfer;
    memcpy(&xfer, rep_p->payload, sizeof(xfer));
    uint64_t present_us = freq ? (((t1 - t0) * 1000000ULL) / freq) : 0ULL;

    /* 7. io_connect_map_memory_into_task (2863, memory_type=0, kIOMapAnywhere) for scanout readback */
    memset(g_ipc_buf, 0, sizeof(g_ipc_buf));
    struct req_map_memory *req_map = (struct req_map_memory *)g_ipc_buf;
    req_map->msgh_body.msgh_descriptor_count = 1U;
    req_map->into_task.name = task_self;
    req_map->into_task.disposition = MACH_MSG_TYPE_COPY_SEND;
    req_map->into_task.type = MACH_MSG_PORT_DESCRIPTOR;
    req_map->NDR = kNDR;
    req_map->memory_type = 0U;
    req_map->address = 0ULL;
    req_map->size = 0ULL;
    req_map->flags = KIOMAP_ANYWHERE;

    mr = mach_msg2_rpc(g_ipc_buf, (uint32_t)sizeof(struct req_map_memory),
                       (uint32_t)sizeof(struct rep_map_memory),
                       bits_complex, connect, reply_port, 2863, 1U);
    if (mr != 0U) {
        log_gop_fail(fd, "map_memory", mr, 0U, connect);
        return;
    }
    struct rep_map_memory *rep_map = (struct rep_map_memory *)g_ipc_buf;
    if (rep_map->RetCode != 0U || rep_map->address == 0ULL || rep_map->size < mode.bytes) {
        log_gop_fail(fd, "map_memory_ret", 0U, rep_map->RetCode, (uint32_t)rep_map->size);
        return;
    }

    const volatile uint32_t *scanout = (const volatile uint32_t *)(uintptr_t)rep_map->address;
    uint32_t pts[6][2] = {
        { w32 / 4U,        h32 / 4U        }, /* TL Red */
        { (w32 * 3U) / 4U, h32 / 4U        }, /* TR Green */
        { w32 / 4U,        (h32 * 3U) / 4U }, /* BL Blue */
        { (w32 * 3U) / 4U, (h32 * 3U) / 4U }, /* BR Checkerboard */
        { w32 / 2U,        h32 / 2U        }, /* Center Yellow */
        { 2U,              2U              }, /* Border White */
    };
    uint32_t got[6];
    uint32_t mismatch = 0U;
    for (int i = 0; i < 6; i++) {
        uint32_t px = pts[i][0];
        uint32_t py = pts[i][1];
        uint32_t exp = pattern_pixel(px, py, w32, h32);
        got[i] = scanout[(size_t)py * (size_t)stride_px + (size_t)px];
        if (got[i] != exp) {
            mismatch |= (1U << i);
        }
    }

    int pass = (xfer.sequence == 1ULL) && (xfer.bytes == mode.bytes) && (mismatch == 0U);
    struct buf_writer w = { g_msg, sizeof(g_msg), 0 };
    bw_puts(&w, pass ? "[EL0_GOP] PASS: mode=" : "[EL0_GOP] FAIL: mode=");
    bw_u64_dec(&w, mode.width);
    bw_putc(&w, 'x');
    bw_u64_dec(&w, mode.height);
    bw_puts(&w, " stride=");
    bw_u64_dec(&w, mode.stride);
    bw_puts(&w, " bytes=");
    bw_u64_dec(&w, xfer.bytes);
    bw_puts(&w, " seq=");
    bw_u64_dec(&w, xfer.sequence);
    bw_puts(&w, " present_us=");
    bw_u64_dec(&w, present_us);
    bw_puts(&w, " map=0x");
    bw_u64_hex(&w, rep_map->address);
    bw_puts(&w, mismatch ? " readback=fail(mask=0x" : " readback=ok(tl=0x");
    if (mismatch) {
        bw_u64_hex(&w, mismatch);
        bw_puts(&w, " tl=0x");
    }
    bw_u64_hex(&w, got[0]);
    bw_puts(&w, ",tr=0x");
    bw_u64_hex(&w, got[1]);
    bw_puts(&w, ",bl=0x");
    bw_u64_hex(&w, got[2]);
    bw_puts(&w, ",br=0x");
    bw_u64_hex(&w, got[3]);
    bw_puts(&w, ",ctr=0x");
    bw_u64_hex(&w, got[4]);
    bw_puts(&w, ",bdr=0x");
    bw_u64_hex(&w, got[5]);
    bw_puts(&w, ")\n");
    write_console(fd, w.buf, w.len);

    /* Free userland staging buffer before hold/reboot. */
    uint32_t unmap_err = 0U;
    darwin_syscall(DARWIN_SYS_munmap, fb_user_va, mode.bytes, 0, 0, 0, 0, &unmap_err);

    /* On live 3200x2136 panel, hold 3.0 seconds so the 4-quadrant image is visible on screen. */
    if (pass && mode.width >= 3000ULL && freq > 0ULL) {
        uint64_t hold_start = read_cntpct();
        uint64_t hold_ticks = freq * 3ULL;
        while ((read_cntpct() - hold_start) < hold_ticks) {
            __asm__ volatile("yield");
        }
    }
}

void stage7_main(void)
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
    uint64_t pac_authed = el0_pac_roundtrip(raw_ptr, 0x51A6E70000000001ULL, &pac_signed);
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

    /* Stage-7B NativeGOPPresenter end-to-end EL0 present + scanout readback. */
    run_gop_test(fd);

    uint32_t reb_err = 0;
    darwin_syscall(DARWIN_SYS_reboot, DARWIN_RB_QUICK_NOSYNC, 0, 0, 0, 0, 0, &reb_err);

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

    cmds = []
    off = 32
    text_seg = None
    linkedit_idx = None
    first_section_off = len(buf)
    old_sig_off = None
    for _ in range(ncmds):
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
            continue
        cmds.append((cmd, payload))
        off += cmdsize

    if text_seg is None:
        raise SystemExit("Mach-O missing __TEXT segment")

    if old_sig_off is not None and old_sig_off < len(buf):
        del buf[old_sig_off:]

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
            1,
            1,
            0,
            0,
        )
        linkedit_idx = len(cmds)
        cmds.append((LC_SEGMENT_64, le_cmd))

    if not any(cmd == LC_BUILD_VERSION for cmd, _ in cmds):
        bv_cmd = struct.pack("<6I", LC_BUILD_VERSION, 24, 2, 0x001B0000, 0x001B0000, 0)
        cmds.append((LC_BUILD_VERSION, bv_cmd))

    sig_cmd_idx = len(cmds)
    cmds.append((LC_CODE_SIGNATURE, struct.pack("<4I", LC_CODE_SIGNATURE, 16, 0, 0)))

    new_sizeofcmds = sum(len(p) for _, p in cmds)
    if 32 + new_sizeofcmds > first_section_off:
        raise SystemExit(f"Load commands ({32 + new_sizeofcmds} B) overflow first section offset ({first_section_off} B)")

    code_limit = align_up(len(buf), 16)
    if len(buf) < code_limit:
        buf.extend(b"\0" * (code_limit - len(buf)))

    ident_bytes = ident.encode("ascii") + b"\0"
    cd_header_len = 88
    ident_offset = cd_header_len
    hash_offset = align_up(ident_offset + len(ident_bytes), 16)
    n_code_slots = (code_limit + SIGN_PAGE_SIZE - 1) // SIGN_PAGE_SIZE
    cd_length = hash_offset + n_code_slots * 32
    superblob_len = 12 + 8 + cd_length

    le_raw = bytearray(cmds[linkedit_idx][1])
    le_vmaddr, _, le_fileoff, _ = struct.unpack_from("<4Q", le_raw, 24)
    new_le_filesize = (code_limit + superblob_len) - le_fileoff
    new_le_vmsize = align_up(new_le_filesize, SIGN_PAGE_SIZE)
    struct.pack_into("<4Q", le_raw, 24, le_vmaddr, new_le_vmsize, le_fileoff, new_le_filesize)
    cmds[linkedit_idx] = (LC_SEGMENT_64, bytes(le_raw))
    cmds[sig_cmd_idx] = (LC_CODE_SIGNATURE, struct.pack("<4I", LC_CODE_SIGNATURE, 16, code_limit, superblob_len))

    struct.pack_into("<8I", buf, 0, magic, cputype, cpusubtype, filetype, len(cmds), new_sizeofcmds, flags, reserved)
    cursor = 32
    for _, payload in cmds:
        buf[cursor : cursor + len(payload)] = payload
        cursor += len(payload)
    if cursor < 32 + sizeofcmds:
        buf[cursor : 32 + sizeofcmds] = b"\0" * (32 + sizeofcmds - cursor)

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
        0,
        n_code_slots,
        code_limit,
        32,
        CS_HASHTYPE_SHA256,
        0,
        SIGN_PAGE_SHIFT,
        0,
        0,
        0,
        0,
        0,
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
    parser.add_argument("--identifier", type=str, default="org.unixnu.violin.stage7-gop-init", help="CodeDirectory identifier")
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

    start_s = out_dir / "stage7-start.S"
    main_c = out_dir / "stage7-main.c"
    start_o = out_dir / "stage7-start.o"
    main_o = out_dir / "stage7-main.o"
    raw_macho = out_dir / "launchd-unsigned.macho"
    signed_macho = out_dir / "launchd.macho"
    stage7_tc = out_dir / "stage7b.trustcache"
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
        ["python3", str(trust_append), str(args.base_trustcache), str(stage7_tc), cdhash.hex()],
        check=True,
    )
    meta["base_trustcache_sha256"] = hashlib.sha256(args.base_trustcache.read_bytes()).hexdigest()
    meta["stage7b_trustcache_sha256"] = hashlib.sha256(stage7_tc.read_bytes()).hexdigest()
    meta["stage7b_trustcache_size"] = stage7_tc.stat().st_size
    meta_json.write_text(json.dumps(meta, indent=2) + "\n", encoding="ascii")

    print(
        f"PASS: built & signed Stage-7B arm64e EL0 /sbin/launchd -> {signed_macho} ({len(signed_bytes)} B, "
        f"{meta['code_slots']}x4K pages, cdhash={cdhash.hex()}) + {stage7_tc} ({meta['stage7b_trustcache_size']} B)"
    )


if __name__ == "__main__":
    main()
