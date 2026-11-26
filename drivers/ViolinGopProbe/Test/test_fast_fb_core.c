/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "ViolinFastFbCore.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_validate(void)
{
    assert(violin_fastfb_validate(3200, 2136, 12800, 3200ULL * 2136 * 4, 12800, 3200ULL * 2136 * 4) == 1);
    assert(violin_fastfb_validate(3200, 2136, 12864, 12864ULL * 2136, 12800, 12800ULL * 2136) == 1);
    assert(violin_fastfb_validate(0, 2136, 12800, 12800ULL * 2136, 12800, 12800ULL * 2136) == 0);
    assert(violin_fastfb_validate(3200, 0, 12800, 12800ULL * 2136, 12800, 12800ULL * 2136) == 0);
    assert(violin_fastfb_validate(3200, 2136, 12796, 12800ULL * 2136, 12800, 12800ULL * 2136) == 0);
    assert(violin_fastfb_validate(3200, 2136, 12800, 12800ULL * 2136 - 4, 12800, 12800ULL * 2136) == 0);
    assert(violin_fastfb_validate(16385, 10, 16385 * 4, 16385ULL * 40, 16385 * 4, 16385ULL * 40) == 0);
}

static void test_split_bands(void)
{
    struct ViolinFbBand bands[VIOLIN_FASTFB_MAX_WORKERS];
    uint32_t n = violin_fastfb_split_bands(2136, 4, bands);
    assert(n == 4);
    assert(bands[0].y_start == 0 && bands[0].y_count == 534);
    assert(bands[1].y_start == 534 && bands[1].y_count == 534);
    assert(bands[2].y_start == 1068 && bands[2].y_count == 534);
    assert(bands[3].y_start == 1602 && bands[3].y_count == 534);

    n = violin_fastfb_split_bands(10, 4, bands);
    assert(n == 4);
    uint32_t total = 0;
    for (uint32_t i = 0; i < n; ++i) {
        assert(bands[i].y_start == total);
        total += bands[i].y_count;
    }
    assert(total == 10);

    n = violin_fastfb_split_bands(2, 4, bands);
    assert(n == 2);
    assert(bands[0].y_start == 0 && bands[0].y_count == 1);
    assert(bands[1].y_start == 1 && bands[1].y_count == 1);
}

static void test_copy_contiguous_and_strided(void)
{
    /* Contiguous 3200x16 test (64-byte aligned rows) */
    const uint32_t w = 3200, h = 16;
    const uint64_t row_b = (uint64_t)w * 4ULL;
    uint8_t *src = (uint8_t *)aligned_alloc(64, row_b * h);
    uint8_t *dst = (uint8_t *)aligned_alloc(64, row_b * h);
    assert(src && dst);
    for (size_t i = 0; i < row_b * h; ++i) {
        src[i] = (uint8_t)((i * 37u + 13u) & 0xffu);
    }
    memset(dst, 0x5A, row_b * h);
    struct ViolinFbBand bands[4];
    uint32_t n = violin_fastfb_split_bands(h, 4, bands);
    for (uint32_t i = 0; i < n; ++i) {
        assert(violin_fastfb_copy_band(dst, row_b, src, row_b, w, bands[i].y_start, bands[i].y_count) == 1);
    }
    assert(memcmp(src, dst, row_b * h) == 0);
    free(src);
    free(dst);

    /* Strided odd width (e.g. 19 px = 76 B) with padded src_stride=128 and dst_stride=80 */
    const uint32_t sw = 19, sh = 7;
    const uint64_t sstride = 128, dstride = 80;
    uint8_t *ss = (uint8_t *)calloc(sh, sstride);
    uint8_t *dd = (uint8_t *)calloc(sh, dstride);
    assert(ss && dd);
    memset(dd, 0xCC, sh * dstride);
    for (uint32_t y = 0; y < sh; ++y) {
        for (uint32_t x = 0; x < sw * 4; ++x) {
            ss[y * sstride + x] = (uint8_t)(y * 17u + x + 1u);
        }
    }
    assert(violin_fastfb_copy_band(dd, dstride, ss, sstride, sw, 0, sh) == 1);
    for (uint32_t y = 0; y < sh; ++y) {
        assert(memcmp(dd + y * dstride, ss + y * sstride, sw * 4) == 0);
        for (uint32_t pad = sw * 4; pad < dstride; ++pad) {
            assert(dd[y * dstride + pad] == 0xCC);
        }
    }
    free(ss);
    free(dd);
}

int main(void)
{
    test_validate();
    test_split_bands();
    test_copy_contiguous_and_strided();
    printf("PASS: test_fast_fb_core (3/3)\n");
    return 0;
}
