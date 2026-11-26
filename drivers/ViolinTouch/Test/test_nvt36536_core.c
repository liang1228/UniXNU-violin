/* SPDX-License-Identifier: Apache-2.0 */
#include "Nvt36536Core.h"
#include "NvtTouchTracker.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct MockNvtChip {
    uint32_t page;
    uint8_t sram[0x200000];
    unsigned writes;
    unsigned reads;
};

static int mock_nvt_xfer(void *ctx, const uint8_t *tx, uint8_t *rx, size_t len)
{
    struct MockNvtChip *m = (struct MockNvtChip *)ctx;
    assert(len >= 2u);
    if (tx[0] == 0xFFu && len == 3u) {
        m->page = ((uint32_t)tx[1] << 15) | ((uint32_t)tx[2] << 7);
        return 0;
    }
    if (tx[0] & 0x80u) {
        uint32_t addr = m->page | (uint32_t)(tx[0] & 0x7Fu);
        ++m->writes;
        if (addr == NVT36536_TX_AUTO_COPY_EN && len >= 2u && tx[1] == 0x56u) {
            m->sram[addr] = 0u; /* instant auto-copy completion */
            return 0;
        }
        if (addr == NVT36536_BOOT_RDY_ADDR && len >= 2u && tx[1] == 1u) {
            m->sram[NVT36536_EVENT_BUF_THP + NVT36536_EVENT_RESET_COMP] = 0xA3u;
            m->sram[NVT36536_EVENT_BUF_THP + NVT36536_EVENT_FWINFO] = 0x17u;
            m->sram[NVT36536_EVENT_BUF_THP + NVT36536_EVENT_FWINFO + 1u] = 0xE8u;
            m->sram[NVT36536_EVENT_BUF_THP + NVT36536_EVENT_FWINFO + 2u] = 40u;
            m->sram[NVT36536_EVENT_BUF_THP + NVT36536_EVENT_FWINFO + 3u] = 60u;
            /* XM_HTC_POLL_INFO frame_len = 5176 (0x1438) at +2 */
            m->sram[NVT36536_XM_HTC_POLL_INFO + 2u] = 0x38u;
            m->sram[NVT36536_XM_HTC_POLL_INFO + 3u] = 0x14u;
            return 0;
        }
        if (addr == NVT36536_EVENT_BUF_THP + NVT36536_EVENT_HOST_CMD && len >= 2u && tx[1] == 0xBFu) {
            m->sram[addr] = 0u; /* command accepted */
            return 0;
        }
        if (addr + (len - 1u) <= sizeof(m->sram)) {
            memcpy(m->sram + addr, tx + 1u, len - 1u);
        }
        return 0;
    } else {
        uint32_t addr = m->page | (uint32_t)(tx[0] & 0x7Fu);
        ++m->reads;
        assert(rx != NULL && len >= 3u);
        rx[0] = 0; rx[1] = 0;
        if (addr == NVT36536_CHIP_VER_TRIM) {
            uint8_t id[6] = {0x15, 0x0E, 0x01, 0x23, 0x65, 0x03};
            memcpy(rx + 2, id, len - 2u < 6u ? len - 2u : 6u);
            return 0;
        }
        if (addr + (len - 2u) <= sizeof(m->sram)) {
            memcpy(rx + 2, m->sram + addr, len - 2u);
        }
        return 0;
    }
}

static void mock_delay(void *ctx, unsigned ms) { (void)ctx; (void)ms; }

static void test_real_fw_and_protocol(const char *fw_path)
{
    FILE *f = fopen(fw_path, "rb");
    assert(f != NULL);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    assert(sz == 253952L);
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    assert(buf && fread(buf, 1, (size_t)sz, f) == (size_t)sz);
    fclose(f);

    struct Nvt36536Fw fw;
    assert(nvt36536_fw_parse(&fw, buf, (size_t)sz) == NVT36536_OK);
    assert(fw.fw_ver == 0x17u);
    assert(fw.cascade_2nd_header == 1u);
    assert(fw.count == 16u);
    assert(fw.part[0].size == 0x1957Bu);
    assert(fw.part[0].crc == nvt36536_crc32_words(buf + fw.part[0].bin_addr, fw.part[0].size, (size_t)sz - fw.part[0].bin_addr));
    assert(fw.part[1].size == 0x156F7u);
    assert(fw.part[1].crc == nvt36536_crc32_words(buf + fw.part[1].bin_addr, fw.part[1].size, (size_t)sz - fw.part[1].bin_addr));

    struct MockNvtChip *hw = (struct MockNvtChip *)calloc(1, sizeof(*hw));
    assert(hw != NULL);
    struct Nvt36536Bus bus = {mock_nvt_xfer, mock_delay, hw};
    struct Nvt36536Chip *chip = (struct Nvt36536Chip *)calloc(1, sizeof(*chip));
    assert(chip != NULL);
    chip->bus = &bus;

    assert(nvt36536_identify(chip) == NVT36536_OK);
    assert(chip->is_cascade == 1);
    assert(chip->event_buf == NVT36536_EVENT_BUF_THP);
    assert(nvt36536_download_firmware(chip, &fw) == NVT36536_OK);
    assert(chip->dl_stage == 0u);

    struct Nvt36536FwInfo info;
    assert(nvt36536_get_fw_info(chip, &info) == NVT36536_OK);
    assert(info.fw_ver == 0x17u && info.x_num == 40u && info.y_num == 60u && info.frame_len == 5176u);
    assert(nvt36536_set_custom_cmd(chip, 0x19u, 0x01u) == NVT36536_OK);
    assert(nvt36536_set_custom_cmd(chip, 0x01u, 0x02u) == NVT36536_OK);

    /* Craft a valid THP frame in chip SRAM at EVENT_BUF_THP + 256 */
    uint8_t *pkt = hw->sram + NVT36536_EVENT_BUF_THP + NVT36536_EVENT_HDR_LEN;
    uint16_t crc = 0x1234u;
    int32_t clen = NVT36536_FINGER_PKT_LEN;
    uint16_t crc_r = (uint16_t)(~crc);
    int32_t clen_r = ~clen;
    pkt[2] = 7; pkt[3] = 0; /* head_cnt=7 */
    memcpy(pkt + 4, &crc, 2);
    memcpy(pkt + 8, &clen, 4);
    memcpy(pkt + 12, &crc_r, 2);
    memcpy(pkt + 16, &clen_r, 4);
    pkt[24] = 4; /* scan_mode */
    pkt[48] = 60; pkt[49] = 40;
    pkt[56] = 0; /* finger matrix */
    int16_t *mat = (int16_t *)(pkt + NVT36536_THP_MATRIX_OFF);
    for (unsigned i = 0; i < NVT36536_NODES; ++i) mat[i] = 1000;
    mat[39 * 60 + 30] = 1600;
    mat[38 * 60 + 30] = 1450;
    mat[39 * 60 + 29] = 1400;

    uint8_t *frame_buf = (uint8_t *)calloc(1, 6600);
    assert(frame_buf != NULL);
    assert(nvt36536_read_thp_frame(chip, frame_buf, 6600) == NVT36536_OK);
    struct Nvt36536FrameMeta meta;
    int16_t parsed[NVT36536_NODES];
    assert(nvt36536_parse_thp_frame(frame_buf, 256 + 5176, &meta, parsed) == NVT36536_OK);
    assert(meta.head_cnt == 7u && meta.num_col == 60u && meta.num_row == 40u);
    assert(parsed[39 * 60 + 30] == 1600);

    free(frame_buf);
    free(chip);
    free(hw);
    free(buf);
}

static void test_tracker_bottom_edge_swipe(void)
{
    struct VTouchTracker *t = (struct VTouchTracker *)calloc(1, sizeof(*t));
    assert(t != NULL);
    vtouch_reset(t);

    int16_t base[VTOUCH_NODES];
    for (int i = 0; i < VTOUCH_NODES; ++i) base[i] = 1000;
    struct VTouchContact out[VTOUCH_SLOTS];

    /* Warm up with baseline frame (scan_mode=2) */
    assert(vtouch_process(t, base, 2u, out, VTOUCH_SLOTS) == -1);
    assert(t->have_reference == 1);

    /* Simulate bottom-edge swipe up from row 39 -> row 20 at col 30 */
    int seen_edge = 0, seen_mid = 0, tid = -1;
    for (int step = 0; step < 12; ++step) {
        int16_t m[VTOUCH_NODES];
        memcpy(m, base, sizeof(m));
        int r = 39 - step;
        m[r * 60 + 30] = 1650;
        if (r > 0) m[(r - 1) * 60 + 30] = 1350;
        if (r < 39) m[(r + 1) * 60 + 30] = 1350;
        m[r * 60 + 29] = 1320;
        m[r * 60 + 31] = 1320;

        int n = vtouch_process(t, m, 4u, out, VTOUCH_SLOTS);
        if (step == 0) {
            assert(n == 0); /* 2-frame onset debounce */
        } else {
            assert(n == 1);
            if (tid < 0) tid = out[0].tracking_id;
            assert(out[0].tracking_id == tid); /* unbroken swipe track */
            int hx, hy;
            vtouch_to_hid_xy(out[0].x, out[0].y, 0u, &hx, &hy);
            if (step == 1 && hy >= 32000) seen_edge = 1; /* within 48 px of bottom edge */
            if (step == 11 && hy < 28000) seen_mid = 1;
        }
    }
    assert(seen_edge == 1 && seen_mid == 1);

    /* Finger lifts -> immediate release on quiet frame */
    int n = vtouch_process(t, base, 4u, out, VTOUCH_SLOTS);
    assert(n == 0);
    free(t);
}

int main(int argc, char **argv)
{
    const char *fw = (argc > 1) ? argv[1] : "/opt/unixnu-out/stage8c-touch/novatek_nt36536_violin_fw_tm00.bin";
    test_real_fw_and_protocol(fw);
    test_tracker_bottom_edge_swipe();
    printf("PASS: test_nvt36536_core (2/2)\n");
    return 0;
}
