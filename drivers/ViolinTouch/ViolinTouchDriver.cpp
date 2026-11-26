// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * ViolinTouchDriver.cpp — XNU kernel driver for Xiaomi Pad 7S Pro (violin / O81A)
 * Novatek NT36536 TDDI Cascade touchscreen on XRING O1 SPI9 (0xE1507000).
 *
 * Security fence:
 *   - All secure SPI9 clocks, resets, and pinctrl go strictly through ARM FF-A v1.0
 *     direct requests to xsp1 (part_id = 0x8001) and EL3 SMC FID_SPI_MISC_PINCTRL.
 *   - OEM touch firmware blob is linked from build-local /opt/unixnu-out/ only
 *     (weak 0-byte fallback when omitted; zero OEM binaries in git).
 */

#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOLib.h>
#include <kern/thread.h>
#include <pexpert/pexpert.h>
#include <stdint.h>
#include <string.h>

#include "XringFfaCore.h"
#include "XringSpi9Core.h"
#include "Nvt36536Core.h"
#include "NvtTouchTracker.h"

extern "C" {
void kprintf(const char *fmt, ...);

/* Weak OEM firmware symbols overridden by build-local Nvt36536FwBlob.o in /opt/unixnu-out/ */
__attribute__((weak)) extern const uint8_t violin_nvt_fw_blob[1] = {0};
__attribute__((weak)) extern const uint32_t violin_nvt_fw_size = 0u;

/* Shared touch seqlock state consumed by ViolinHidInput */
volatile uint32_t violin_touch_seq = 0u;
volatile uint32_t violin_touch_count = 0u;
volatile uint32_t violin_touch_hid_reports = 0u;
volatile int violin_touch_xs[VTOUCH_SLOTS] = {};
volatile int violin_touch_ys[VTOUCH_SLOTS] = {};
volatile int violin_touch_ids[VTOUCH_SLOTS] = {};

/* Live diagnostic telemetry */
volatile uint32_t violin_touch_stage = 0u;
volatile uint32_t violin_touch_ready = 0u;
volatile uint32_t violin_touch_frames = 0u;
volatile uint32_t violin_touch_bad_frames = 0u;
volatile uint32_t violin_touch_irq_count = 0u;
volatile uint32_t violin_touch_contacts_seen = 0u;

typedef void (*violin_touch_sink_fn)(void *ctx);
static violin_touch_sink_fn gTouchSink = nullptr;
static void *gTouchSinkCtx = nullptr;
static bool gTouchThreadStarted = false;

void violin_touch_set_sink(violin_touch_sink_fn fn, void *ctx)
{
    gTouchSinkCtx = ctx;
    __asm__ volatile("dmb ish" ::: "memory");
    gTouchSink = fn;
}

void violin_touch_publish_contacts(unsigned count, const int *ids, const int *xs, const int *ys)
{
    if (count > VTOUCH_SLOTS) count = VTOUCH_SLOTS;
    uint32_t seq = violin_touch_seq + 1u;
    violin_touch_seq = seq;
    __asm__ volatile("dmb ish" ::: "memory");
    violin_touch_count = count;
    for (unsigned i = 0u; i < count; ++i) {
        violin_touch_ids[i] = ids[i];
        violin_touch_xs[i] = xs[i];
        violin_touch_ys[i] = ys[i];
    }
    __asm__ volatile("dmb ish" ::: "memory");
    violin_touch_seq = seq + 1u;

    violin_touch_sink_fn fn = gTouchSink;
    void *ctx = gTouchSinkCtx;
    if (fn != nullptr) {
        fn(ctx);
    }
}
} // extern "C"

namespace {

constexpr uint32_t kDwGpioDdr     = 0x04u;
constexpr uint32_t kDwGpioDr0     = 0x08u; /* pins 0..15 with write-enable mask in [31:16] */
constexpr uint32_t kDwGpioDr1     = 0x0Cu; /* pins 16..31 with write-enable mask in [31:16] */
constexpr uint32_t kDwGpioExtPort = 0x50u;

struct XnuSpi9Hw {
    volatile uint32_t *spiRegs;
    volatile uint32_t *gpio2Regs;
};

void xnuGpio2SetBit(XnuSpi9Hw *hw, uint32_t bit, int high)
{
    uint32_t reg = (bit >= 16u) ? kDwGpioDr1 : kDwGpioDr0;
    uint32_t sub = (bit >= 16u) ? (bit - 16u) : bit;
    uint32_t val = (1u << (sub + 16u)) | ((high ? 1u : 0u) << sub);
    hw->gpio2Regs[reg / 4u] = val;
    __asm__ volatile("dsb sy" ::: "memory");
}

void xnuSmcCall(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
                uint64_t out[8], void *)
{
    register uint64_t x0 __asm__("x0") = a0;
    register uint64_t x1 __asm__("x1") = a1;
    register uint64_t x2 __asm__("x2") = a2;
    register uint64_t x3 __asm__("x3") = a3;
    register uint64_t x4 __asm__("x4") = a4;
    register uint64_t x5 __asm__("x5") = a5;
    register uint64_t x6 __asm__("x6") = a6;
    register uint64_t x7 __asm__("x7") = a7;
    __asm__ volatile(
        "smc #0"
        : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3),
          "+r"(x4), "+r"(x5), "+r"(x6), "+r"(x7)
        :
        : "memory");
    out[0] = x0; out[1] = x1; out[2] = x2; out[3] = x3;
    out[4] = x4; out[5] = x5; out[6] = x6; out[7] = x7;
}

uint32_t spi9Rd32(void *ctx, uint32_t off)
{
    auto *hw = static_cast<XnuSpi9Hw *>(ctx);
    uint32_t v = hw->spiRegs[off / 4u];
    __asm__ volatile("dsb ld" ::: "memory");
    return v;
}

void spi9Wr32(void *ctx, uint32_t off, uint32_t val)
{
    auto *hw = static_cast<XnuSpi9Hw *>(ctx);
    hw->spiRegs[off / 4u] = val;
    __asm__ volatile("dsb st" ::: "memory");
}

void spi9SetCs(void *ctx, int asserted)
{
    auto *hw = static_cast<XnuSpi9Hw *>(ctx);
    /* GPIO_080 (bit 16 on dw_gpio2) is active-low CS via XRING bit-masked DR1 (0x0C) */
    xnuGpio2SetBit(hw, XRING_SPI9_CS_GPIO_BIT, asserted ? 0 : 1);
}

void spi9DelayUs(void *, uint32_t us)
{
    IODelay(us);
}

int nvtBusXfer(void *ctx, const uint8_t *tx, uint8_t *rx, size_t len)
{
    return xring_spi9_xfer(static_cast<struct XringSpi9 *>(ctx), tx, rx, len);
}

void nvtBusDelayMs(void *, unsigned ms)
{
    if (ms > 0u) IOSleep(ms);
}

void violinTouchThread(void *, wait_result_t)
{
    /* Wait briefly for early display/storage/HID attach to settle */
    IOSleep(2500u);

    unsigned isQemu = 0u;
    PE_parse_boot_argn("violin_qemu", &isQemu, sizeof(isQemu));
    if (isQemu != 0u) {
        kprintf("[VIOLIN_TOUCH] QEMU mode: skipping physical SPI9/FF-A touch bring-up\n");
        thread_terminate(current_thread());
        return;
    }

    /* Live Lock Screen swipe-up trace proved row 0 is bottom edge -> flip Y (orient=4) by default */
    unsigned orient = 4u;
    PE_parse_boot_argn("touch-orient", &orient, sizeof(orient));
    unsigned baudr = 4u;
    PE_parse_boot_argn("spi9-baudr", &baudr, sizeof(baudr));
    if (baudr < 2u || (baudr & 1u)) baudr = 4u;

    violin_touch_stage = 1u;
    struct XringFfaClient ffa;
    int ffaRc = xring_ffa_init(&ffa, xnuSmcCall, nullptr);
    kprintf("[VIOLIN_TOUCH] ffa_init rc=%d ver=0x%x sender=0x%x dest=0x%x\n",
            ffaRc, ffa.version, ffa.sender_id, ffa.dest_id);
    if (ffaRc != 0) {
        thread_terminate(current_thread());
        return;
    }

    violin_touch_stage = 2u;
    const uint64_t gpioPageBase = XRING_DW_GPIO2_PHYS_BASE & ~0xFFFULL;
    const uint64_t gpioPageOff  = XRING_DW_GPIO2_PHYS_BASE & 0xFFFULL;
    IODeviceMemory *gpioMem = IODeviceMemory::withRange(gpioPageBase, 0x1000ULL);
    IODeviceMemory *spiMem  = IODeviceMemory::withRange(XRING_SPI9_PHYS_BASE, XRING_SPI9_MMIO_SIZE);
    IOMemoryMap *gpioMap = gpioMem ? gpioMem->map(kIOMapAnywhere | kIOMapInhibitCache) : nullptr;
    IOMemoryMap *spiMap  = spiMem  ? spiMem->map(kIOMapAnywhere | kIOMapInhibitCache)  : nullptr;
    OSSafeReleaseNULL(gpioMem);
    OSSafeReleaseNULL(spiMem);
    if (!gpioMap || !spiMap || !gpioMap->getVirtualAddress() || !spiMap->getVirtualAddress()) {
        kprintf("[VIOLIN_TOUCH] FAIL: MMIO map failed gpio=%p spi=%p\n", gpioMap, spiMap);
        OSSafeReleaseNULL(gpioMap);
        OSSafeReleaseNULL(spiMap);
        thread_terminate(current_thread());
        return;
    }

    XnuSpi9Hw hw = {
        reinterpret_cast<volatile uint32_t *>(spiMap->getVirtualAddress()),
        reinterpret_cast<volatile uint32_t *>(gpioMap->getVirtualAddress() + gpioPageOff),
    };

    /* Configure GPIO_080 (CS) as output HIGH and GPIO_076 (IRQ) as input BEFORE pinctrl/clocks */
    spi9SetCs(&hw, 0);
    uint32_t ddr = hw.gpio2Regs[kDwGpioDdr / 4u];
    ddr |= (1u << XRING_SPI9_CS_GPIO_BIT);
    ddr &= ~(1u << XRING_TOUCH_IRQ_GPIO_BIT);
    hw.gpio2Regs[kDwGpioDdr / 4u] = ddr;
    __asm__ volatile("dsb sy" ::: "memory");
    spi9SetCs(&hw, 1);
    IODelay(2u);
    uint32_t csLo = (hw.gpio2Regs[kDwGpioExtPort / 4u] >> XRING_SPI9_CS_GPIO_BIT) & 1u;
    spi9SetCs(&hw, 0);
    IODelay(2u);
    uint32_t csHi = (hw.gpio2Regs[kDwGpioExtPort / 4u] >> XRING_SPI9_CS_GPIO_BIT) & 1u;
    kprintf("[VIOLIN_TOUCH] gpio2_cs_check lo=%u hi=%u ext=0x%x ddr=0x%x\n",
            csLo, csHi, hw.gpio2Regs[kDwGpioExtPort / 4u], hw.gpio2Regs[kDwGpioDdr / 4u]);

    violin_touch_stage = 3u;
    uint32_t m76_0 = 0xFFu, m77_0 = 0xFFu, m80_0 = 0xFFu;
    (void)xring_ffa_ioc_func_get(&ffa, 76u, &m76_0);
    (void)xring_ffa_ioc_func_get(&ffa, 77u, &m77_0);
    (void)xring_ffa_ioc_func_get(&ffa, 80u, &m80_0);

    uint64_t clkDiv = 0ULL;
    int pwrRc = xring_spi9_secure_power_up(&ffa, &clkDiv);

    uint32_t m76_1 = 0xFFu, m77_1 = 0xFFu, m78_1 = 0xFFu, m79_1 = 0xFFu, m80_1 = 0xFFu;
    (void)xring_ffa_ioc_func_get(&ffa, 76u, &m76_1);
    (void)xring_ffa_ioc_func_get(&ffa, 77u, &m77_1);
    (void)xring_ffa_ioc_func_get(&ffa, 78u, &m78_1);
    (void)xring_ffa_ioc_func_get(&ffa, 79u, &m79_1);
    (void)xring_ffa_ioc_func_get(&ffa, 80u, &m80_1);
    kprintf("[VIOLIN_TOUCH] spi9_pwr rc=%d stp=%u out0=0x%llx mret=0x%llx div=%llu irq=%u ddr=0x%x\n",
            pwrRc, ffa.last_step,
            static_cast<unsigned long long>(ffa.last_out0),
            static_cast<unsigned long long>(ffa.last_msg_ret),
            static_cast<unsigned long long>(clkDiv),
            (hw.gpio2Regs[kDwGpioExtPort / 4u] >> XRING_TOUCH_IRQ_GPIO_BIT) & 1u,
            hw.gpio2Regs[kDwGpioDdr / 4u]);
    kprintf("[VIOLIN_TOUCH] ioc_mux pre=(76:%u,77:%u,80:%u) post=(76:%u,77:%u,78:%u,79:%u,80:%u)\n",
            m76_0 & 7u, m77_0 & 7u, m80_0 & 7u,
            m76_1 & 7u, m77_1 & 7u, m78_1 & 7u, m79_1 & 7u, m80_1 & 7u);
    if (pwrRc != 0) {
        OSSafeReleaseNULL(gpioMap);
        OSSafeReleaseNULL(spiMap);
        thread_terminate(current_thread());
        return;
    }

    violin_touch_stage = 4u;
    struct XringSpi9 spi;
    struct XringSpi9Ops spiOps = {spi9Rd32, spi9Wr32, spi9SetCs, spi9DelayUs, &hw};
    struct Nvt36536Bus nvtBus = {nvtBusXfer, nvtBusDelayMs, &spi};

    auto *chip = static_cast<struct Nvt36536Chip *>(IOMallocZero(sizeof(struct Nvt36536Chip)));
    auto *tracker = static_cast<struct VTouchTracker *>(IOMallocZero(sizeof(struct VTouchTracker)));
    auto *frameBuf = static_cast<uint8_t *>(IOMallocZero(NVT36536_EVENT_HDR_LEN + NVT36536_MAX_FRAME_LEN + 64u));
    auto *matrix = static_cast<int16_t *>(IOMallocZero(sizeof(int16_t) * NVT36536_NODES));
    if (!chip || !tracker || !frameBuf || !matrix) {
        kprintf("[VIOLIN_TOUCH] FAIL: IOMallocZero failed\n");
        thread_terminate(current_thread());
        return;
    }

    /* Try endian_bit=1 first (matching spi-dw-core.c is_spi_dma), fallback to endian_bit=0 if ID fails */
    int idRc = -1;
    int endianUsed = 1;
    for (int tryEndian = 1; tryEndian >= 0; --tryEndian) {
        int spiRc = xring_spi9_init(&spi, &spiOps, baudr, tryEndian);
        kprintf("[VIOLIN_TOUCH] spi9_init(endian=%d,baudr=%u) rc=%d idr=0x%08x ver=0x%08x fifo=%u\n",
                tryEndian, baudr, spiRc, spi.idr, spi.version, spi.fifo_len);
        if (spiRc != 0) continue;
        memset(chip, 0, sizeof(*chip));
        chip->bus = &nvtBus;
        idRc = nvt36536_identify(chip);
        kprintf("[VIOLIN_TOUCH] identify(endian=%d) rc=%d id=%02x:%02x:%02x:%02x:%02x:%02x casc=%d\n",
                tryEndian, idRc,
                chip->id[0], chip->id[1], chip->id[2], chip->id[3], chip->id[4], chip->id[5],
                chip->is_cascade);
        if (idRc == NVT36536_OK) {
            endianUsed = tryEndian;
            break;
        }
    }
    if (idRc != NVT36536_OK) {
        kprintf("[VIOLIN_TOUCH] FAIL: NVT-36536 identify failed\n");
        thread_terminate(current_thread());
        return;
    }

    violin_touch_stage = 5u;
    if (violin_nvt_fw_size < 4096u) {
        kprintf("[VIOLIN_TOUCH] FAIL: firmware blob absent (size=%u)\n", violin_nvt_fw_size);
        thread_terminate(current_thread());
        return;
    }
    struct Nvt36536Fw fw;
    int parseRc = nvt36536_fw_parse(&fw, violin_nvt_fw_blob, violin_nvt_fw_size);
    kprintf("[VIOLIN_TOUCH] fw_parse rc=%d size=%u ver=0x%02x casc2=%u parts=%u\n",
            parseRc, violin_nvt_fw_size, fw.fw_ver, fw.cascade_2nd_header, fw.count);
    if (parseRc != NVT36536_OK) {
        thread_terminate(current_thread());
        return;
    }

    violin_touch_stage = 6u;
    int dlRc = nvt36536_download_firmware(chip, &fw);
    kprintf("[VIOLIN_TOUCH] fw_download rc=%d att=%u stg=%u rst=%02x:%02x crcf=%02x:%02x r_crc=(0x%08x,0x%08x)\n",
            dlRc, chip->dl_attempt, chip->dl_stage,
            chip->dl_reset_state[0], chip->dl_reset_state[1],
            chip->bld_crc_flags[0], chip->bld_crc_flags[1],
            chip->r_ilm_crc, chip->r_dlm_crc);
    if (dlRc != NVT36536_OK) {
        thread_terminate(current_thread());
        return;
    }

    violin_touch_stage = 7u;
    struct Nvt36536FwInfo info;
    (void)nvt36536_get_fw_info(chip, &info);
    int c1 = nvt36536_set_custom_cmd(chip, 0x19u, 0x01u); /* idle baseline update */
    int c2 = nvt36536_set_custom_cmd(chip, 0x01u, 0x02u); /* op_mode = 2 */
    kprintf("[VIOLIN_TOUCH] PASS: fw_ver=0x%02x grid=%ux%u flen=%u cmds=(%d,%d) endian=%d orient=%u\n",
            info.fw_ver, info.x_num, info.y_num, info.frame_len, c1, c2, endianUsed, orient);

    vtouch_reset(tracker);
    violin_touch_stage = 8u;
    __atomic_store_n(&violin_touch_ready, 1u, __ATOMIC_RELEASE);

    uint16_t lastHeadCnt = 0xFFFFu;
    unsigned idlePolls = 0u;
    unsigned loggedFrames = 0u;
    unsigned loggedContacts = 0u;
    int prevVisible = 0;

    for (;;) {
        uint32_t irqLevel = (hw.gpio2Regs[kDwGpioExtPort / 4u] >> XRING_TOUCH_IRQ_GPIO_BIT) & 1u;
        if (irqLevel != 0u) {
            ++idlePolls;
            if (idlePolls < 8u) {
                IOSleep(2u);
                continue;
            }
            /* Fallback poll every ~16 ms in case IRQ line is edge-only or already serviced */
            idlePolls = 0u;
        } else {
            __atomic_add_fetch(&violin_touch_irq_count, 1u, __ATOMIC_RELAXED);
            idlePolls = 0u;
        }

        int rdRc = nvt36536_read_thp_frame(chip, frameBuf, NVT36536_EVENT_HDR_LEN + NVT36536_MAX_FRAME_LEN);
        if (rdRc != NVT36536_OK) {
            __atomic_add_fetch(&violin_touch_bad_frames, 1u, __ATOMIC_RELAXED);
            IOSleep(4u);
            continue;
        }

        struct Nvt36536FrameMeta meta;
        int pRc = nvt36536_parse_thp_frame(frameBuf, NVT36536_EVENT_HDR_LEN + chip->frame_len, &meta, matrix);
        if (pRc != NVT36536_OK) {
            uint32_t bad = __atomic_add_fetch(&violin_touch_bad_frames, 1u, __ATOMIC_RELAXED);
            if (bad <= 5u) {
                const uint8_t *pkt = frameBuf + NVT36536_EVENT_HDR_LEN;
                kprintf("[VIOLIN_TOUCH] bad_frame #%u hdr=%02x %02x %02x %02x %02x %02x %02x %02x\n",
                        bad, pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5], pkt[8], pkt[9]);
            }
            IOSleep(4u);
            continue;
        }

        if (meta.head_cnt == lastHeadCnt) {
            IOSleep(2u);
            continue;
        }
        lastHeadCnt = meta.head_cnt;

        uint32_t fc = __atomic_add_fetch(&violin_touch_frames, 1u, __ATOMIC_RELAXED);
        if (loggedFrames < 5u) {
            ++loggedFrames;
            kprintf("[VIOLIN_TOUCH] frame #%u cnt=%u mode=%u type=%u grid=%ux%u clen=0x%x m0=%d\n",
                    fc, meta.head_cnt, meta.scan_mode, meta.frame_data_type,
                    meta.num_row, meta.num_col, meta.crc_len, matrix[0]);
        }

        /* Only feed mutual-cap finger frames (type 0/3/14) into finger tracker */
        if (meta.frame_data_type != 0u && meta.frame_data_type != 3u && meta.frame_data_type != 14u) {
            IOSleep(2u);
            continue;
        }

        struct VTouchContact contacts[VTOUCH_SLOTS];
        int n = vtouch_process(tracker, matrix, meta.scan_mode, contacts, VTOUCH_SLOTS);
        if (n < 0) {
            /* Baseline still warming up */
            IOSleep(2u);
            continue;
        }

        if (n > 0 || prevVisible > 0) {
            int ids[VTOUCH_SLOTS], xs[VTOUCH_SLOTS], ys[VTOUCH_SLOTS];
            for (int i = 0; i < n; ++i) {
                ids[i] = contacts[i].tracking_id;
                vtouch_to_hid_xy(contacts[i].x, contacts[i].y, orient, &xs[i], &ys[i]);
            }
            violin_touch_publish_contacts(static_cast<unsigned>(n), ids, xs, ys);
            if (n > 0) {
                uint32_t cs = __atomic_add_fetch(&violin_touch_contacts_seen, 1u, __ATOMIC_RELAXED);
                if (loggedContacts < 16u || (cs % 60u) == 0u) {
                    ++loggedContacts;
                    kprintf("[VIOLIN_TOUCH] contact #%u n=%d id0=%d hid=(%d,%d) raw=(%d,%d) pk=%d\n",
                            cs, n, ids[0], xs[0], ys[0], contacts[0].x, contacts[0].y, contacts[0].peak);
                }
            }
            prevVisible = n;
        }
        IOSleep((n > 0 || irqLevel == 0u) ? 1u : 2u);
    }
}

} // namespace

extern "C" void violin_touch_start(void)
{
    if (gTouchThreadStarted) return;
    unsigned en = 1u;
    PE_parse_boot_argn("violin-touch", &en, sizeof(en));
    if (en == 0u) {
        kprintf("[VIOLIN_TOUCH] disabled by boot-arg violin-touch=0\n");
        return;
    }
    gTouchThreadStarted = true;
    thread_t thr = nullptr;
    if (kernel_thread_start(violinTouchThread, nullptr, &thr) == KERN_SUCCESS) {
        thread_deallocate(thr);
        kprintf("[VIOLIN_TOUCH] started touch bring-up thread\n");
    } else {
        gTouchThreadStarted = false;
        kprintf("[VIOLIN_TOUCH] FAIL: kernel_thread_start failed\n");
    }
}
