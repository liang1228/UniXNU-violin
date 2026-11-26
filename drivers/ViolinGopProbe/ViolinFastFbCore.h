/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/*
 * ViolinFastFbCore.h — Pure C11 bounds, horizontal band splitting, and
 * 64-byte GPR non-temporal (stnp) Write-Combining framebuffer copy core.
 *
 * Strictly integer-only (zero FP/NEON registers) so it is 100% safe inside
 * XNU kernel threads on arm64e without kernel_fpu_begin().
 */
#ifndef VIOLIN_FAST_FB_CORE_H
#define VIOLIN_FAST_FB_CORE_H

#include <stddef.h>
#include <stdint.h>

#define VIOLIN_FASTFB_MAX_WORKERS 8u
#define VIOLIN_FASTFB_MAX_DIM     16384u

struct ViolinFbBand {
    uint32_t y_start;
    uint32_t y_count;
};

static inline int violin_fastfb_validate(uint32_t width, uint32_t height,
                                         uint64_t src_stride, uint64_t src_len,
                                         uint64_t dst_stride, uint64_t dst_len)
{
    if (width == 0u || height == 0u ||
        width > VIOLIN_FASTFB_MAX_DIM || height > VIOLIN_FASTFB_MAX_DIM) {
        return 0;
    }
    uint64_t row_bytes = (uint64_t)width * 4ULL;
    if (src_stride < row_bytes || dst_stride < row_bytes) {
        return 0;
    }
    if (src_stride > UINT64_MAX / (uint64_t)height ||
        dst_stride > UINT64_MAX / (uint64_t)height) {
        return 0;
    }
    uint64_t src_need = src_stride * (uint64_t)(height - 1u) + row_bytes;
    uint64_t dst_need = dst_stride * (uint64_t)(height - 1u) + row_bytes;
    if (src_len < src_need || dst_len < dst_need) {
        return 0;
    }
    return 1;
}

static inline uint32_t violin_fastfb_split_bands(uint32_t height, uint32_t nworkers,
                                                 struct ViolinFbBand *bands)
{
    if (height == 0u || nworkers == 0u || bands == NULL) {
        return 0u;
    }
    if (nworkers > VIOLIN_FASTFB_MAX_WORKERS) {
        nworkers = VIOLIN_FASTFB_MAX_WORKERS;
    }
    if (nworkers > height) {
        nworkers = height;
    }
    uint32_t base = height / nworkers;
    uint32_t rem = height % nworkers;
    uint32_t y = 0u;
    for (uint32_t i = 0u; i < nworkers; ++i) {
        uint32_t cnt = base + (i < rem ? 1u : 0u);
        bands[i].y_start = y;
        bands[i].y_count = cnt;
        y += cnt;
    }
    return nworkers;
}

static inline void violin_fastfb_copy_row_wc(uint8_t *dst, const uint8_t *src, uint64_t bytes)
{
    uint64_t off = 0ULL;
#if defined(__aarch64__)
    if ((((uintptr_t)dst & 15ULL) == 0ULL) && (((uintptr_t)src & 15ULL) == 0ULL)) {
        for (; off + 64ULL <= bytes; off += 64ULL) {
            uint64_t a, b, c, d, e, f, g, h;
            const uint8_t *sp = src + off;
            uint8_t *dp = dst + off;
            __asm__ volatile(
                "ldp %0, %1, [%8, #0]\n\t"
                "ldp %2, %3, [%8, #16]\n\t"
                "ldp %4, %5, [%8, #32]\n\t"
                "ldp %6, %7, [%8, #48]\n\t"
                "stnp %0, %1, [%9, #0]\n\t"
                "stnp %2, %3, [%9, #16]\n\t"
                "stnp %4, %5, [%9, #32]\n\t"
                "stnp %6, %7, [%9, #48]\n\t"
                : "=&r"(a), "=&r"(b), "=&r"(c), "=&r"(d),
                  "=&r"(e), "=&r"(f), "=&r"(g), "=&r"(h)
                : "r"(sp), "r"(dp)
                : "memory");
        }
    }
#endif
    for (; off + 8ULL <= bytes; off += 8ULL) {
        uint64_t v;
        __builtin_memcpy(&v, src + off, 8u);
        __builtin_memcpy(dst + off, &v, 8u);
    }
    for (; off + 4ULL <= bytes; off += 4ULL) {
        uint32_t v;
        __builtin_memcpy(&v, src + off, 4u);
        __builtin_memcpy(dst + off, &v, 4u);
    }
    for (; off < bytes; ++off) {
        dst[off] = src[off];
    }
}

static inline int violin_fastfb_copy_band(uint8_t *dst_base, uint64_t dst_stride,
                                          const uint8_t *src_base, uint64_t src_stride,
                                          uint32_t width, uint32_t y_start, uint32_t y_count)
{
    if (dst_base == NULL || src_base == NULL || width == 0u || y_count == 0u) {
        return 0;
    }
    uint64_t row_bytes = (uint64_t)width * 4ULL;
    if (src_stride < row_bytes || dst_stride < row_bytes) {
        return 0;
    }
    if (src_stride == row_bytes && dst_stride == row_bytes) {
        /* Contiguous band: single streaming pass minimizes loop overhead. */
        violin_fastfb_copy_row_wc(dst_base + (uint64_t)y_start * dst_stride,
                                  src_base + (uint64_t)y_start * src_stride,
                                  row_bytes * (uint64_t)y_count);
        return 1;
    }
    for (uint32_t r = 0u; r < y_count; ++r) {
        uint64_t y = (uint64_t)y_start + (uint64_t)r;
        violin_fastfb_copy_row_wc(dst_base + y * dst_stride,
                                  src_base + y * src_stride,
                                  row_bytes);
    }
    return 1;
}

#endif /* VIOLIN_FAST_FB_CORE_H */
