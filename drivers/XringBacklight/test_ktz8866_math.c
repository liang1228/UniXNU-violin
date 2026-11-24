/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* Host ASan/UBSan unit tests for Ktz8866Math.h (11-bit split, 16.16 nits, safe test levels). */

#include "Ktz8866Math.h"

#include <assert.h>
#include <stdio.h>

int main(void)
{
    /* 1. Exhaustive 11-bit round-trip 0..2047. */
    for (uint16_t lvl = 0; lvl <= KTZ8866_LEVEL_MAX; lvl++) {
        uint8_t lsb = 0xFFu, msb = 0xFFu;
        ktz8866_encode_level(lvl, &lsb, &msb);
        assert((lsb & ~0x07u) == 0u);
        assert(ktz8866_decode_level(lsb, msb) == lvl);
    }

    /* 2. Clamp overflow above 2047. */
    {
        uint8_t lsb = 0, msb = 0;
        ktz8866_encode_level(4095u, &lsb, &msb);
        assert(lsb == 0x07u && msb == 0xFFu);
        assert(ktz8866_decode_level(lsb, msb) == 2047u);
    }

    /* 3. Known EDK2 value 0x133 = 307 -> msb = 0x26, lsb = 0x03. */
    {
        uint8_t lsb = 0, msb = 0;
        ktz8866_encode_level(0x133u, &lsb, &msb);
        assert(lsb == 0x03u);
        assert(msb == 0x26u);
        assert(ktz8866_decode_level(0x03u, 0x26u) == 0x133u);
    }

    /* 4. Signed 16.16 nits conversion boundary & monotonicity checks. */
    assert(ktz8866_nits1616_to_level(0) == 0u);
    assert(ktz8866_nits1616_to_level(-1) == 0u);
    assert(ktz8866_nits1616_to_level(1) == 1u);
    assert(ktz8866_nits1616_to_level(500 << 16) == 2047u);
    assert(ktz8866_nits1616_to_level(900 << 16) == 2047u);

    uint16_t prev = 0;
    for (int n = 1; n <= 500; n++) {
        uint16_t cur = ktz8866_nits1616_to_level(n << 16);
        assert(cur >= prev);
        assert(cur >= 1u && cur <= 2047u);
        prev = cur;
    }

    /* 5. Level -> nits1616 -> level round-trip accuracy (exact!). */
    for (uint16_t lvl = 0; lvl <= KTZ8866_LEVEL_MAX; lvl++) {
        int32_t n16 = ktz8866_level_to_nits1616(lvl);
        uint16_t rt = ktz8866_nits1616_to_level(n16);
        assert(rt == lvl);
    }

    /* 6. Milli-nits range. */
    assert(ktz8866_level_to_millinits(0u) == 0u);
    assert(ktz8866_level_to_millinits(1u) == 2000u);
    assert(ktz8866_level_to_millinits(2047u) == 500000u);

    /* 7. Safe visible dimming test levels are strictly non-zero, distinct, and bounded. */
    const uint16_t samples[] = { 0u, 50u, 307u, 600u, 1024u, 1750u, 2047u };
    for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); i++) {
        uint16_t lo = 0, hi = 0;
        ktz8866_safe_test_levels(samples[i], &lo, &hi);
        assert(lo >= 80u && lo <= 1800u);
        assert(hi >= 120u && hi <= 1800u);
        assert(lo < hi);
    }

    printf("PASS: test_ktz8866_math (all 7 suites, 2048 round-trips)\n");
    return 0;
}
