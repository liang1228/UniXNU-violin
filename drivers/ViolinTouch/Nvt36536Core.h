/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Nvt36536Core.h — Pure C11 protocol core for Novatek NT36536 TDDI Cascade
 * on Xiaomi Pad 7S Pro (violin / o81a).
 *
 * Register maps & THP layout verified against:
 *   - references/violin-v-oss/xiaomi-modules/touch_driver/o81a/nt36xxx_mem_map.h
 *   - references/violin-v-oss/xiaomi-modules/touch_driver/o81a/nt36xxx_fw_update.c
 *   - references/violin-v-oss/xiaomi-modules/touch_driver/o81a/nt36xxx.c (lines 2687..2757, 3048..3242)
 *   - live /odm/firmware/novatek_nt36536_violin_fw_tm00.bin (253,952 B, fw_ver=0x17)
 */
#ifndef NVT36536_CORE_H
#define NVT36536_CORE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define NVT36536_TRANSFER_LEN      4096u
#define NVT36536_MAX_FRAME_LEN     6144u
#define NVT36536_EVENT_HDR_LEN     256u
#define NVT36536_THP_MATRIX_OFF    64u   /* frame_data = frame_data_packet + 64 (nt36xxx.c:2726) */
#define NVT36536_MAX_PARTITIONS    24u
#define NVT36536_ROWS              40u
#define NVT36536_COLS              60u
#define NVT36536_NODES             (NVT36536_ROWS * NVT36536_COLS)

/* Fixed HW control addresses (hw_reg_addr_info) */
#define NVT36536_ENG_RST_ADDR      0x7FFF80u
#define NVT36536_CHIP_VER_TRIM     0x1FB104u
#define NVT36536_ENB_CASC_ADDR     0x1FB12Cu
#define NVT36536_SWRST_SIF_ADDR    0x1FB43Eu

/* NT36536_cascade_memory_map (TOUCH_THP_SUPPORT=1) */
#define NVT36536_EVENT_BUF_THP     0x133300u
#define NVT36536_EVENT_BUF_SINGLE  0x130900u
#define NVT36536_BOOT_RDY_ADDR     0x1FB50Du
#define NVT36536_TX_AUTO_COPY_EN   0x1FC825u
#define NVT36536_ILM_DES_ADDR      0x1FCC30u
#define NVT36536_ILM_LEN_ADDR      0x1FCC34u
#define NVT36536_G_ILM_CRC_ADDR    0x1FCC38u
#define NVT36536_DLM_DES_ADDR      0x1FCC40u
#define NVT36536_DLM_LEN_ADDR      0x1FCC44u
#define NVT36536_G_DLM_CRC_ADDR    0x1FCC48u
#define NVT36536_R_ILM_CRC_ADDR    0x1FCC7Cu
#define NVT36536_R_DLM_CRC_ADDR    0x1FCC80u
#define NVT36536_BLD_CRC_FLAG      0x1FB532u
#define NVT36536_XM_HTC_POLL_INFO  0x109F78u

#define NVT36536_EVENT_HOST_CMD    0x50u
#define NVT36536_EVENT_RESET_COMP  0x60u
#define NVT36536_EVENT_FWINFO      0x78u
#define NVT36536_HOST_ENABLE_CRC   0xAEu
#define NVT36536_RESET_STATE_INIT  0xA0u
#define NVT36536_RESET_STATE_MAX   0xAFu

#define NVT36536_FINGER_PKT_LEN    0x04C3
#define NVT36536_STYLUS_PKT_LEN    0x050D

enum {
    NVT36536_OK = 0,
    NVT36536_ERR_PARAM = -1,
    NVT36536_ERR_BUS = -2,
    NVT36536_ERR_CHIP = -3,
    NVT36536_ERR_FW = -4,
    NVT36536_ERR_TIMEOUT = -5,
    NVT36536_ERR_FRAME = -6,
};

struct Nvt36536Bus {
    int (*xfer)(void *ctx, const uint8_t *tx, uint8_t *rx, size_t len);
    void (*delay_ms)(void *ctx, unsigned ms);
    void *ctx;
};

struct Nvt36536Partition {
    uint32_t bin_addr;
    uint32_t sram_addr;
    uint32_t size;
    uint32_t crc;
    char name[12];
};

struct Nvt36536Fw {
    const uint8_t *data;
    size_t size;
    uint32_t need_write_size;
    uint8_t fw_ver;
    uint8_t cascade_2nd_header;
    uint8_t spi_dma_div;
    unsigned count;
    struct Nvt36536Partition part[NVT36536_MAX_PARTITIONS];
};

struct Nvt36536FwInfo {
    uint8_t fw_ver;
    uint8_t x_num;
    uint8_t y_num;
    uint8_t fw_type;
    uint16_t pid;
    uint16_t frame_len;
};

struct Nvt36536FrameMeta {
    uint16_t head_cnt;
    uint16_t frame_no;
    uint16_t cur_frame_len;
    uint8_t scan_mode;
    uint8_t frame_data_type;
    uint8_t num_col;
    uint8_t num_row;
    int32_t crc_len;
};

struct Nvt36536Chip {
    const struct Nvt36536Bus *bus;
    uint8_t id[6];
    int is_cascade;
    uint32_t event_buf;
    uint16_t frame_len;
    unsigned dl_attempt;
    unsigned dl_stage;
    int dl_rc;
    uint8_t dl_reset_state[5];
    uint8_t bld_crc_flags[2];
    uint32_t r_ilm_crc;
    uint32_t r_dlm_crc;
    uint8_t tx_buf[NVT36536_EVENT_HDR_LEN + NVT36536_MAX_FRAME_LEN + 16u];
    uint8_t rx_buf[NVT36536_EVENT_HDR_LEN + NVT36536_MAX_FRAME_LEN + 16u];
};

static inline uint32_t nvt36536_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint16_t nvt36536_u16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline uint32_t nvt36536_crc32_words(const uint8_t *data, size_t len, size_t avail)
{
    uint32_t c = 0xFFFFFFFFu;
    size_t words = (len + 4u) / 4u;
    for (size_t i = 0u; i < words; ++i) {
        uint32_t w = 0u;
        for (unsigned b = 0u; b < 4u; ++b) {
            size_t at = i * 4u + b;
            if (at < avail) w |= (uint32_t)data[at] << (8u * b);
        }
        c ^= w;
        for (unsigned j = 0u; j < 32u; ++j) {
            c = (c & 0x80000000u) ? ((c << 1) ^ 0x04C11DB7u) : (c << 1);
        }
    }
    return c;
}

static inline void nvt36536_delay(struct Nvt36536Chip *c, unsigned ms)
{
    if (c && c->bus && c->bus->delay_ms) c->bus->delay_ms(c->bus->ctx, ms);
}

static inline int nvt36536_bus_write(struct Nvt36536Chip *c, size_t len)
{
    if (!c || !c->bus || !c->bus->xfer || len == 0u || len > NVT36536_TRANSFER_LEN + 1u) {
        return NVT36536_ERR_PARAM;
    }
    c->tx_buf[0] |= 0x80u;
    return c->bus->xfer(c->bus->ctx, c->tx_buf, NULL, len) ? NVT36536_ERR_BUS : NVT36536_OK;
}

static inline int nvt36536_set_page(struct Nvt36536Chip *c, uint32_t addr)
{
    c->tx_buf[0] = 0xFFu;
    c->tx_buf[1] = (uint8_t)((addr >> 15) & 0xFFu);
    c->tx_buf[2] = (uint8_t)((addr >> 7) & 0xFFu);
    return nvt36536_bus_write(c, 3u);
}

static inline int nvt36536_write(struct Nvt36536Chip *c, uint32_t addr, const uint8_t *data, size_t len)
{
    if (!c || !data || len == 0u || len > NVT36536_TRANSFER_LEN) return NVT36536_ERR_PARAM;
    int r = nvt36536_set_page(c, addr);
    if (r) return r;
    c->tx_buf[0] = (uint8_t)(addr & 0x7Fu);
    memcpy(c->tx_buf + 1, data, len);
    return nvt36536_bus_write(c, len + 1u);
}

static inline int nvt36536_write_byte(struct Nvt36536Chip *c, uint32_t addr, uint8_t v)
{
    return nvt36536_write(c, addr, &v, 1u);
}

/* Full-duplex read: tx = [offset & 0x7F, 0, ...], rx data starts at rx_buf[2] */
static inline int nvt36536_read_at(struct Nvt36536Chip *c, uint8_t off7, uint8_t *out, size_t len)
{
    if (!c || !c->bus || !c->bus->xfer || !out || len == 0u ||
        len + 2u > sizeof(c->rx_buf)) {
        return NVT36536_ERR_PARAM;
    }
    /* For large continuous reads (> transfer_len), reuse rx_buf zeroed as TX (offset at byte 0). */
    if (len + 2u <= sizeof(c->tx_buf)) {
        memset(c->tx_buf, 0, len + 2u);
        c->tx_buf[0] = (uint8_t)(off7 & 0x7Fu);
        if (c->bus->xfer(c->bus->ctx, c->tx_buf, c->rx_buf, len + 2u)) return NVT36536_ERR_BUS;
    } else {
        /* 2-byte address+dummy + continuous rx using rx_buf as both? No, use chunked stack?
         * Better: zero rx_buf and pass tx=NULL? No, byte 0 MUST be off7!
         * Split into 1-byte header? No, CS must stay asserted! So read in <= NVT36536_TRANSFER_LEN chunks
         * OR expand tx_buf? We'll make tx_buf big enough for one full THP frame (6600 bytes)! */
        return NVT36536_ERR_PARAM;
    }
    memcpy(out, c->rx_buf + 2, len);
    return NVT36536_OK;
}

static inline int nvt36536_read(struct Nvt36536Chip *c, uint32_t addr, uint8_t *out, size_t len)
{
    int r = nvt36536_set_page(c, addr);
    if (r) return r;
    return nvt36536_read_at(c, (uint8_t)(addr & 0x7Fu), out, len);
}

static inline int nvt36536_fw_parse(struct Nvt36536Fw *fw, const uint8_t *d, size_t size)
{
    if (!fw || !d || size < 0x1000u) return NVT36536_ERR_FW;
    memset(fw, 0, sizeof(*fw));
    fw->data = d;
    fw->size = size;

    /* Find "NVT" or "MOD" 4K sector end flag */
    size_t sectors = size / 4096u;
    for (size_t s = sectors; s > 0u; --s) {
        const uint8_t *tag = d + s * 4096u - 3u;
        if ((tag[0] == 'N' && tag[1] == 'V' && tag[2] == 'T') ||
            (tag[0] == 'M' && tag[1] == 'O' && tag[2] == 'D')) {
            fw->need_write_size = (uint32_t)(s * 4096u);
            break;
        }
    }
    if (fw->need_write_size < 4096u) return NVT36536_ERR_FW;
    uint8_t ver = d[fw->need_write_size - 4096u];
    uint8_t ver_bar = d[fw->need_write_size - 4095u];
    if ((uint8_t)(ver + ver_bar) != 0xFFu) return NVT36536_ERR_FW;
    fw->fw_ver = ver;

    uint32_t end = nvt36536_u32le(d);
    if (end < 0x40u || end > size) return NVT36536_ERR_FW;

    uint32_t pos = 0x30u;
    while (pos + 0x10u <= end) {
        if (nvt36536_u32le(d + pos + 4u) != 0u && nvt36536_u32le(d + pos + 8u) == 0u) {
            end = pos + 0x10u;
            break;
        }
        pos += 0x10u;
    }
    unsigned info_sec_num = (end - 0x30u) / 0x10u;
    fw->cascade_2nd_header = (uint8_t)((d[0x20] & 0x02u) >> 1);
    if (fw->cascade_2nd_header) {
        info_sec_num += 1u;
        fw->spi_dma_div = (uint8_t)(d[0x29] & 0x01u);
        end *= 2u;
        if (end > size) return NVT36536_ERR_FW;
    }
    unsigned ovly_info = (d[0x28] & 0x10u) >> 4;
    unsigned ovly_sec_num = ovly_info ? (d[0x28] & 0x0Fu) : 0u;
    unsigned total = 2u + ovly_sec_num + info_sec_num;
    if (total > NVT36536_MAX_PARTITIONS) return NVT36536_ERR_FW;
    fw->count = total;

    int found_hdr = 0;
    for (unsigned i = 0u; i < total; ++i) {
        struct Nvt36536Partition *p = &fw->part[i];
        if (i < 2u) {
            p->bin_addr  = nvt36536_u32le(d + i * 12u);
            p->sram_addr = nvt36536_u32le(d + 4u + i * 12u);
            p->size      = nvt36536_u32le(d + 8u + i * 12u);
            p->crc       = nvt36536_u32le(d + 0x18u + i * 4u);
            memcpy(p->name, i == 0u ? "ILM" : "DLM", 4u);
        } else if (i < 2u + info_sec_num) {
            if (!found_hdr) pos = 0x30u + 0x10u * (i - 2u);
            else if (fw->cascade_2nd_header) pos = end - 0x10u;
            if (pos + 0x10u > size) return NVT36536_ERR_FW;
            p->sram_addr = nvt36536_u32le(d + pos);
            p->size      = nvt36536_u32le(d + pos + 4u);
            p->bin_addr  = nvt36536_u32le(d + pos + 8u);
            p->crc       = nvt36536_u32le(d + pos + 12u);
            if (p->bin_addr < end && p->size != 0u) {
                memcpy(p->name, "Header", 7u);
                found_hdr = 1;
            } else {
                memcpy(p->name, "Info", 5u);
            }
        } else {
            pos = fw->part[1].bin_addr + 0x10u * (i - 2u - info_sec_num);
            if (pos + 0x10u > size) return NVT36536_ERR_FW;
            p->sram_addr = nvt36536_u32le(d + pos);
            p->size      = nvt36536_u32le(d + pos + 4u);
            p->bin_addr  = nvt36536_u32le(d + pos + 8u);
            p->crc       = nvt36536_u32le(d + pos + 12u);
            memcpy(p->name, "Ovly", 5u);
        }
        if ((uint64_t)p->bin_addr + (uint64_t)p->size > size) return NVT36536_ERR_FW;
    }
    return NVT36536_OK;
}

static inline int nvt36536_bootloader_reset(struct Nvt36536Chip *c)
{
    int r = nvt36536_write_byte(c, NVT36536_SWRST_SIF_ADDR, 0x69u);
    nvt36536_delay(c, 5u);
    return r;
}

static inline int nvt36536_identify(struct Nvt36536Chip *c)
{
    if (!c || !c->bus) return NVT36536_ERR_PARAM;
    int r = nvt36536_write_byte(c, NVT36536_ENG_RST_ADDR, 0x5Au);
    if (r) return r;
    nvt36536_delay(c, 11u);

    int matched = 0;
    for (unsigned retry = 0u; retry < 5u && !matched; ++retry) {
        if ((r = nvt36536_bootloader_reset(c)) != 0) return r;
        if ((r = nvt36536_set_page(c, NVT36536_CHIP_VER_TRIM)) != 0) return r;
        memset(c->tx_buf, 0, 7u);
        c->tx_buf[0] = (uint8_t)(NVT36536_CHIP_VER_TRIM & 0x7Fu);
        if ((r = nvt36536_bus_write(c, 7u)) != 0) return r;
        uint8_t id[6] = {0};
        if ((r = nvt36536_read_at(c, (uint8_t)(NVT36536_CHIP_VER_TRIM & 0x7Fu), id, 6u)) != 0) return r;
        memcpy(c->id, id, 6u);
        /* trim_id_table for NT36536: {0x14/0x15, *, *, 0x23, 0x65, 0x03} */
        if ((id[0] == 0x14u || id[0] == 0x15u) && id[3] == 0x23u && id[4] == 0x65u && id[5] == 0x03u) {
            matched = 1;
        } else {
            nvt36536_delay(c, 10u);
        }
    }
    if (!matched) return NVT36536_ERR_CHIP;

    uint8_t enb_casc = 0u;
    if ((r = nvt36536_read(c, NVT36536_ENB_CASC_ADDR, &enb_casc, 1u)) != 0) return r;
    c->is_cascade = (enb_casc & 0x01u) == 0u ? 1 : 0;
    c->event_buf = c->is_cascade ? NVT36536_EVENT_BUF_THP : NVT36536_EVENT_BUF_SINGLE;
    c->frame_len = 5176u;
    return NVT36536_OK;
}

static inline int nvt36536_write_3(struct Nvt36536Chip *c, uint32_t addr, uint32_t v)
{
    uint8_t b[3] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16)};
    return nvt36536_write(c, addr, b, 3u);
}

static inline int nvt36536_write_4(struct Nvt36536Chip *c, uint32_t addr, uint32_t v)
{
    uint8_t b[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
    return nvt36536_write(c, addr, b, 4u);
}

static inline int nvt36536_download_firmware(struct Nvt36536Chip *c, const struct Nvt36536Fw *fw)
{
    if (!c || !fw || fw->count < 2u || !fw->part[0].size || !fw->part[1].size) {
        return NVT36536_ERR_PARAM;
    }
    int r = 0;
    for (unsigned attempt = 0u; attempt < 3u; ++attempt) {
        c->dl_attempt = attempt + 1u;

        c->dl_stage = 1u;
        if ((r = nvt36536_bootloader_reset(c)) != 0) { c->dl_rc = r; continue; }

        c->dl_stage = 2u;
        if ((r = nvt36536_write_3(c, NVT36536_ILM_DES_ADDR, fw->part[0].sram_addr)) ||
            (r = nvt36536_write_3(c, NVT36536_ILM_LEN_ADDR, fw->part[0].size)) ||
            (r = nvt36536_write_4(c, NVT36536_G_ILM_CRC_ADDR, fw->part[0].crc)) ||
            (r = nvt36536_write_3(c, NVT36536_DLM_DES_ADDR, fw->part[1].sram_addr)) ||
            (r = nvt36536_write_3(c, NVT36536_DLM_LEN_ADDR, fw->part[1].size)) ||
            (r = nvt36536_write_4(c, NVT36536_G_DLM_CRC_ADDR, fw->part[1].crc))) {
            c->dl_rc = r; continue;
        }

        if (fw->cascade_2nd_header) {
            c->dl_stage = 3u;
            if ((r = nvt36536_write_byte(c, NVT36536_TX_AUTO_COPY_EN, 0x56u)) != 0) {
                c->dl_rc = r; continue;
            }
        }

        c->dl_stage = 4u;
        r = 0;
        for (unsigned i = 0u; i < fw->count && r == 0; ++i) {
            const struct Nvt36536Partition *p = &fw->part[i];
            if (p->size == 0u) continue;
            uint32_t rem = p->size + 1u;
            if ((uint64_t)p->bin_addr + rem > fw->size) rem = p->size;
            uint32_t sram = p->sram_addr;
            uint32_t bin = p->bin_addr;
            while (rem > 0u) {
                uint32_t chunk = rem < NVT36536_TRANSFER_LEN ? rem : NVT36536_TRANSFER_LEN;
                r = nvt36536_write(c, sram, fw->data + bin, chunk);
                if (r != 0) break;
                sram += chunk;
                bin += chunk;
                rem -= chunk;
            }
        }
        if (r != 0) { c->dl_rc = r; continue; }

        if (fw->cascade_2nd_header) {
            c->dl_stage = 5u;
            r = NVT36536_ERR_TIMEOUT;
            for (unsigned poll = 0u; poll < 200u; ++poll) {
                uint8_t v = 0xFFu;
                int rr = nvt36536_read(c, NVT36536_TX_AUTO_COPY_EN, &v, 1u);
                if (rr != 0) { r = rr; break; }
                if (v == 0u) { r = 0; break; }
                nvt36536_delay(c, 1u);
            }
            if (r != 0) { c->dl_rc = r; continue; }
        }

        c->dl_stage = 6u;
        uint8_t zeros[7] = {0};
        if ((r = nvt36536_write(c, c->event_buf + NVT36536_EVENT_RESET_COMP, zeros, sizeof(zeros))) ||
            (r = nvt36536_write_byte(c, c->event_buf + NVT36536_EVENT_HOST_CMD, NVT36536_HOST_ENABLE_CRC))) {
            c->dl_rc = r; continue;
        }

        c->dl_stage = 7u;
        if ((r = nvt36536_write_byte(c, NVT36536_BOOT_RDY_ADDR, 1u)) != 0) {
            c->dl_rc = r; continue;
        }
        nvt36536_delay(c, 5u);

        c->dl_stage = 8u;
        r = NVT36536_ERR_TIMEOUT;
        for (unsigned poll = 0u; poll <= 20u; ++poll) {
            uint8_t st[5] = {0};
            int rr = nvt36536_read(c, c->event_buf + NVT36536_EVENT_RESET_COMP, st, 5u);
            if (rr != 0) { r = rr; break; }
            memcpy(c->dl_reset_state, st, 5u);
            if (st[0] >= NVT36536_RESET_STATE_INIT && st[0] <= NVT36536_RESET_STATE_MAX) {
                r = 0;
                break;
            }
            nvt36536_delay(c, 10u);
        }
        if (r == 0) {
            c->dl_stage = 0u;
            c->dl_rc = 0;
            return NVT36536_OK;
        }
        c->dl_rc = r;
    }

    /* Capture BLD CRC telemetry on failure */
    (void)nvt36536_read(c, NVT36536_BLD_CRC_FLAG, c->bld_crc_flags, 2u);
    uint8_t b4[4] = {0};
    if (nvt36536_read(c, NVT36536_R_ILM_CRC_ADDR, b4, 4u) == 0) c->r_ilm_crc = nvt36536_u32le(b4);
    if (nvt36536_read(c, NVT36536_R_DLM_CRC_ADDR, b4, 4u) == 0) c->r_dlm_crc = nvt36536_u32le(b4);
    return r ? r : NVT36536_ERR_TIMEOUT;
}

static inline int nvt36536_get_fw_info(struct Nvt36536Chip *c, struct Nvt36536FwInfo *info)
{
    if (!c || !info) return NVT36536_ERR_PARAM;
    memset(info, 0, sizeof(*info));
    uint8_t b[38] = {0};
    for (unsigned attempt = 0u; attempt < 4u; ++attempt) {
        int r = nvt36536_read(c, c->event_buf + NVT36536_EVENT_FWINFO, b, sizeof(b));
        if (r) return r;
        if ((uint8_t)(b[0] + b[1]) == 0xFFu) {
            info->fw_ver  = b[0];
            info->x_num   = b[2];
            info->y_num   = b[3];
            info->fw_type = b[13];
            info->pid     = (uint16_t)(((uint16_t)b[35] << 8) | b[34]);
            break;
        }
    }
    uint8_t poll[39] = {0};
    if (nvt36536_read(c, NVT36536_XM_HTC_POLL_INFO, poll, sizeof(poll)) == 0) {
        uint16_t flen = nvt36536_u16le(poll + 2u);
        if (flen >= 4864u && flen <= NVT36536_MAX_FRAME_LEN) {
            c->frame_len = flen;
        }
    }
    info->frame_len = c->frame_len;
    (void)nvt36536_set_page(c, c->event_buf);
    return NVT36536_OK;
}

static inline int nvt36536_set_custom_cmd(struct Nvt36536Chip *c, uint8_t sub_cmd, uint16_t val)
{
    nvt36536_delay(c, 25u);
    for (unsigned tries = 0u; tries < 5u; ++tries) {
        uint8_t cmd[5] = {0xBFu, sub_cmd, 0x00u, (uint8_t)(val & 0xFFu), (uint8_t)(val >> 8)};
        int r = nvt36536_write(c, c->event_buf + NVT36536_EVENT_HOST_CMD, cmd, sizeof(cmd));
        if (r) return r;
        nvt36536_delay(c, 20u);
        uint8_t st = 0xFFu;
        r = nvt36536_read(c, c->event_buf + NVT36536_EVENT_HOST_CMD, &st, 1u);
        if (r) return r;
        if (st == 0u) return NVT36536_OK;
    }
    return NVT36536_ERR_TIMEOUT;
}

/* Read 256-byte EventBuf + frame_len THP packet in ONE continuous CS-low SPI burst (matches nt36xxx.c:3050) */
static inline int nvt36536_read_thp_frame(struct Nvt36536Chip *c, uint8_t *out_frame, size_t out_cap)
{
    if (!c || !out_frame) return NVT36536_ERR_PARAM;
    size_t total = (size_t)NVT36536_EVENT_HDR_LEN + (size_t)c->frame_len;
    if (total > out_cap || total + 2u > sizeof(c->tx_buf) || total + 2u > sizeof(c->rx_buf)) {
        return NVT36536_ERR_PARAM;
    }
    return nvt36536_read(c, c->event_buf, out_frame, total);
}

/* Parse THP frame_data_packet at frame + 256 and extract 40x60 int16 matrix at pkt + 64 */
static inline int nvt36536_parse_thp_frame(const uint8_t *frame, size_t frame_bytes,
                                           struct Nvt36536FrameMeta *meta,
                                           int16_t matrix_out[NVT36536_NODES])
{
    if (!frame || frame_bytes < NVT36536_EVENT_HDR_LEN + NVT36536_THP_MATRIX_OFF + NVT36536_NODES * 2u) {
        return NVT36536_ERR_PARAM;
    }
    const uint8_t *pkt = frame + NVT36536_EVENT_HDR_LEN;
    uint16_t crc     = nvt36536_u16le(pkt + 4u);
    int32_t  crc_len = (int32_t)nvt36536_u32le(pkt + 8u);
    uint16_t crc_r   = nvt36536_u16le(pkt + 12u);
    int32_t  crc_r_l = (int32_t)nvt36536_u32le(pkt + 16u);

    if (crc_r != (uint16_t)(~crc) || crc_r_l != ~crc_len) {
        return NVT36536_ERR_FRAME;
    }
    if (meta) {
        meta->head_cnt        = nvt36536_u16le(pkt + 2u);
        meta->scan_mode       = pkt[24];
        meta->frame_no        = nvt36536_u16le(pkt + 28u);
        meta->cur_frame_len   = nvt36536_u16le(pkt + 44u);
        meta->num_col         = pkt[48];
        meta->num_row         = pkt[49];
        meta->frame_data_type = pkt[56];
        meta->crc_len         = crc_len;
    }
    if (matrix_out) {
        const uint8_t *m = pkt + NVT36536_THP_MATRIX_OFF;
        for (unsigned i = 0u; i < NVT36536_NODES; ++i) {
            matrix_out[i] = (int16_t)nvt36536_u16le(m + i * 2u);
        }
    }
    return NVT36536_OK;
}

#endif /* NVT36536_CORE_H */
