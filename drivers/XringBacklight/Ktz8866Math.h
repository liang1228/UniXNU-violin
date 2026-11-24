// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * Ktz8866Math.h — Pure KTZ8866A 11-bit Brightness & CoreBrightness 16.16 Nits Math
 *
 * Shared between the XNU ViolinBacklight driver and host ASan/UBSan unit tests.
 * Verified against references/violin-v-oss/graphics/dpu/litexdm/src/connector/panel/panel_backlight_ktz8866.c
 * and source/UniXNU/docs/zh/drivers/sheng-backlight.md.
 */
#ifndef VIOLIN_KTZ8866_MATH_H
#define VIOLIN_KTZ8866_MATH_H

#include <stdint.h>

#define KTZ8866_I2C_ADDR          0x11u
#define KTZ8866_REG_DISP_ID       0x01u
#define KTZ8866_REG_DISP_BC1      0x02u
#define KTZ8866_REG_DISP_BC2      0x03u
#define KTZ8866_REG_DISP_BB_LSB   0x04u
#define KTZ8866_REG_DISP_BB_MSB   0x05u
#define KTZ8866_REG_DISP_BL_EN    0x08u
#define KTZ8866_REG_DISP_FLAGS    0x0Fu
#define KTZ8866_REG_FULL_CURRENT  0x15u

#define KTZ8866_LEVEL_MAX         2047u
#define KTZ8866_NITS_MIN          2u
#define KTZ8866_NITS_MID          140u
#define KTZ8866_NITS_MAX          500u

static inline uint16_t ktz8866_decode_level(uint8_t lsb, uint8_t msb)
{
    return (uint16_t)((((uint16_t)msb) << 3) | (uint16_t)(lsb & 0x07u));
}

static inline void ktz8866_encode_level(uint16_t level, uint8_t *outLsb, uint8_t *outMsb)
{
    if (level > KTZ8866_LEVEL_MAX) {
        level = KTZ8866_LEVEL_MAX;
    }
    if (outLsb != 0) {
        *outLsb = (uint8_t)(level & 0x07u);
    }
    if (outMsb != 0) {
        *outMsb = (uint8_t)((level >> 3) & 0xFFu);
    }
}

/* Convert signed 16.16 fixed-point nits (brightness-nits) -> KTZ8866 11-bit level (0..2047). */
static inline uint16_t ktz8866_nits1616_to_level(int32_t nits1616)
{
    if (nits1616 <= 0) {
        return 0u;
    }
    uint64_t max1616 = ((uint64_t)KTZ8866_NITS_MAX) << 16;
    uint64_t v = (uint64_t)(uint32_t)nits1616;
    if (v >= max1616) {
        return KTZ8866_LEVEL_MAX;
    }
    uint64_t scaled = (v * (uint64_t)KTZ8866_LEVEL_MAX + (max1616 / 2u)) / max1616;
    if (scaled < 1u) {
        scaled = 1u;
    }
    if (scaled > KTZ8866_LEVEL_MAX) {
        scaled = KTZ8866_LEVEL_MAX;
    }
    return (uint16_t)scaled;
}

/* Convert KTZ8866 11-bit level (0..2047) -> milli-nits (0..500000) for BrightnessMilliNits. */
static inline uint32_t ktz8866_level_to_millinits(uint16_t level)
{
    if (level == 0u) {
        return 0u;
    }
    if (level > KTZ8866_LEVEL_MAX) {
        level = KTZ8866_LEVEL_MAX;
    }
    uint64_t maxMilli = (uint64_t)KTZ8866_NITS_MAX * 1000u;
    uint64_t mn = ((uint64_t)level * maxMilli + (KTZ8866_LEVEL_MAX / 2u)) / KTZ8866_LEVEL_MAX;
    if (mn < (uint64_t)KTZ8866_NITS_MIN * 1000u) {
        mn = (uint64_t)KTZ8866_NITS_MIN * 1000u;
    }
    return (uint32_t)mn;
}

/* Convert KTZ8866 11-bit level (0..2047) -> signed 16.16 fixed-point nits. */
static inline int32_t ktz8866_level_to_nits1616(uint16_t level)
{
    if (level == 0u) {
        return 0;
    }
    if (level > KTZ8866_LEVEL_MAX) {
        level = KTZ8866_LEVEL_MAX;
    }
    uint64_t max1616 = ((uint64_t)KTZ8866_NITS_MAX) << 16;
    uint64_t v = ((uint64_t)level * max1616 + (KTZ8866_LEVEL_MAX / 2u)) / KTZ8866_LEVEL_MAX;
    return (int32_t)v;
}

/* Compute safe, visibly distinct, non-zero dimming test levels around initLevel. */
static inline void ktz8866_safe_test_levels(uint16_t initLevel, uint16_t *outLow, uint16_t *outHigh)
{
    uint16_t base = initLevel;
    if (base < 160u) {
        base = 320u;
    }
    uint32_t low = ((uint32_t)base * 3u) / 4u;
    if (low < 120u) {
        low = 120u;
    }
    if (low == initLevel && low > 80u) {
        low -= 32u;
    }
    uint32_t high = ((uint32_t)base * 5u) / 4u;
    if (high > 1800u) {
        high = 1800u;
    }
    if (high <= low + 32u) {
        high = (low + 128u <= 1800u) ? (low + 128u) : 1800u;
    }
    if (outLow != 0) {
        *outLow = (uint16_t)low;
    }
    if (outHigh != 0) {
        *outHigh = (uint16_t)high;
    }
}

#endif /* VIOLIN_KTZ8866_MATH_H */
