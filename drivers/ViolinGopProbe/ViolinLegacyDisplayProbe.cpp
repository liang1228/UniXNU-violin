// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * ViolinLegacyDisplayProbe — Stage-7/8C board probe for NativeLegacyDisplay.
 *
 * Deferred kext loader + OSMetaClass registration + telemetry callbacks +
 * Stage-8C High-Hz Write-Combining 4-worker GPR streaming presenter via
 * native_legacy_gpu_offer / native_legacy_gpu_complete (zero edits to source/UniXNU).
 */

#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <kern/thread.h>
#include <libkern/OSKextLib.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSMetaClass.h>
#include <pexpert/pexpert.h>

#include "ViolinFastFbCore.h"

extern "C" {
void kprintf(const char *fmt, ...);
void flush_dcache64(addr64_t addr, unsigned count, int phys);
void native_legacy_gpu_complete(void *display, int status);

/* Globalized static constructor from NativeLegacyDisplay.late.o (__mod_init_func removed). */
void native_legacy_display_static_init(void) __asm__("__GLOBAL__sub_I_NativeLegacyDisplay.cpp");
IOService *native_legacy_display_allocate(void);

/* Disabled strong fallbacks for optional Adreno / SM8550-DPU / GPU-trace weak_import symbols
 * (strong non-weak definitions avoid ld64 coalesced weak-bind chained fixup imports in MH_FILESET). */
bool native_adreno_fences(uint32_t *submitted, uint32_t *retired)
{
    if (submitted) *submitted = 0u;
    if (retired) *retired = 0u;
    return false;
}
bool native_adreno_fences_detail(uint32_t *submitted, uint32_t *retired, uint32_t *detail)
{
    if (submitted) *submitted = 0u;
    if (retired) *retired = 0u;
    if (detail) { detail[0] = 0u; detail[1] = 0u; detail[2] = 0u; }
    return false;
}
int native_gpu_trace_enabled(void) { return 0; }
void native_gpu_trace_record(uint32_t event, uint32_t pid, const uint64_t *values, uint32_t count)
{
    (void)event; (void)pid; (void)values; (void)count;
}
uint32_t native_ufs_dpu_map(unsigned slot, const uint64_t *pages, unsigned count)
{
    (void)slot; (void)pages; (void)count;
    return 0u;
}
volatile uint32_t native_ufs_dpu_state = 0u;

extern volatile uint32_t native_legacy_swapstat[16];
extern volatile uint32_t native_legacy_formats[10];

volatile uint32_t violin_legacy_stage = 0;
volatile uint32_t violin_legacy_pm_ready = 0;
volatile uint32_t violin_legacy_default_surface_ok = 0;
volatile uint32_t violin_legacy_clients = 0;
volatile uint32_t violin_legacy_validations = 0;
volatile uint32_t violin_legacy_rejected = 0;
volatile uint32_t violin_legacy_transfers = 0;
volatile uint32_t violin_legacy_retirements = 0;
volatile uint32_t violin_legacy_vsync_ticks = 0;
volatile uint64_t violin_legacy_last_copy_us = 0;
volatile uint64_t violin_legacy_copy_min_us = UINT64_MAX;
volatile uint64_t violin_legacy_copy_max_us = 0;
volatile uint64_t violin_legacy_copy_sum_us = 0;
volatile uint32_t violin_legacy_copy_count = 0;
volatile uint32_t violin_fastfb_active = 0;
volatile uint32_t violin_fastfb_frames = 0;
volatile uint32_t violin_fastfb_fallbacks = 0;
volatile uint32_t violin_dsi_tmg_regs[8] = {};

static IOService *gViolinLegacyDisplay = nullptr;
static volatile uint32_t *gViolinGopFb = nullptr;
static uint32_t gViolinGopWidth = 0;
static uint32_t gViolinGopHeight = 0;
static uint64_t gViolinGopBytes = 0;
static uint64_t gViolinGopStride = 0;

/* Stage-8C Write-Combining GOP mapping & striped 4-worker GPR presenter */
static IOMemoryDescriptor *gViolinWcDesc = nullptr;
static IOMemoryMap *gViolinWcMap = nullptr;
static uint8_t *gViolinWcVa = nullptr;
static uint64_t gViolinWcBytes = 0;

static IOLock *gFastFbLock = nullptr;
static uint32_t gFastFbWorkers = 0;
static uint32_t gFastFbFlush = 1;
static bool gFastFbBusy = false;
static uint32_t gFastFbGen = 0;
static uint32_t gFastFbRemaining = 0;
static void *gJobDisplay = nullptr;
static IOMemoryDescriptor *gJobMemory = nullptr;
static IOMemoryMap *gJobSrcMap = nullptr;
static const uint8_t *gJobSrcVa = nullptr;
static uint64_t gJobSrcStride = 0;
static uint32_t gJobWidth = 0;
static uint32_t gJobHeight = 0;
static uint64_t gJobStartTicks = 0;
static uint32_t gJobMapGen = 0;
static bool gJobMapFailed = false;

static inline uint64_t readCntpct(void)
{
    uint64_t v = 0;
    __asm__ volatile("isb\n\tmrs %0, cntpct_el0" : "=r"(v));
    return v;
}

void native_legacy_copy_timing_observed(uint64_t ticks, uint64_t bytes);

static void violin_fastfb_worker(void *arg, wait_result_t)
{
    const uint32_t idx = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(arg));
    uint32_t myGen = 0;

    for (;;) {
        IOLockLock(gFastFbLock);
        while (gFastFbGen == myGen) {
            IOLockSleep(gFastFbLock, &gFastFbGen, THREAD_UNINT);
        }
        myGen = gFastFbGen;
        IOMemoryDescriptor *mem = gJobMemory;
        const uint64_t srcStride = gJobSrcStride;
        const uint32_t width = gJobWidth;
        const uint32_t height = gJobHeight;
        const uint32_t nworkers = gFastFbWorkers;
        IOLockUnlock(gFastFbLock);

        bool failed = false;
        const uint8_t *srcVa = nullptr;

        if (idx == 0u) {
            IOMemoryMap *smap = mem ? mem->map(kIOMapAnywhere | kIOMapReadOnly | kIOMapCopybackCache) : nullptr;
            uint64_t need = srcStride * static_cast<uint64_t>(height);
            if (!smap || !smap->getVirtualAddress() || smap->getLength() < need) {
                OSSafeReleaseNULL(smap);
                failed = true;
            } else {
                srcVa = reinterpret_cast<const uint8_t *>(smap->getVirtualAddress());
            }
            IOLockLock(gFastFbLock);
            gJobSrcMap = smap;
            gJobSrcVa = srcVa;
            gJobMapFailed = failed;
            gJobMapGen = myGen;
            IOLockWakeup(gFastFbLock, &gJobMapGen, false);
            IOLockUnlock(gFastFbLock);
        } else {
            IOLockLock(gFastFbLock);
            while (gJobMapGen != myGen) {
                IOLockSleep(gFastFbLock, &gJobMapGen, THREAD_UNINT);
            }
            failed = gJobMapFailed;
            srcVa = gJobSrcVa;
            IOLockUnlock(gFastFbLock);
        }

        if (!failed && srcVa != nullptr && gViolinWcVa != nullptr) {
            struct ViolinFbBand bands[VIOLIN_FASTFB_MAX_WORKERS];
            uint32_t nbands = violin_fastfb_split_bands(height, nworkers, bands);
            if (idx < nbands && bands[idx].y_count > 0u) {
                uint64_t bandOff = static_cast<uint64_t>(bands[idx].y_start) * srcStride;
                uint64_t bandLen = static_cast<uint64_t>(bands[idx].y_count) * srcStride;
                if (gFastFbFlush != 0u && bandLen <= 0xFFFFFFFFULL) {
                    flush_dcache64(reinterpret_cast<addr64_t>(srcVa + bandOff),
                                   static_cast<unsigned>(bandLen), 0);
                }
                (void)violin_fastfb_copy_band(gViolinWcVa, gViolinGopStride,
                                              srcVa, srcStride,
                                              width, bands[idx].y_start, bands[idx].y_count);
                __asm__ volatile("dsb oshst" ::: "memory");
            }
        }

        if (__atomic_sub_fetch(&gFastFbRemaining, 1u, __ATOMIC_ACQ_REL) == 0u) {
            uint64_t endTicks = readCntpct();
            void *disp = nullptr;
            IOMemoryDescriptor *relMem = nullptr;
            IOMemoryMap *relMap = nullptr;
            uint64_t startTicks = 0;
            bool jobFail = false;

            IOLockLock(gFastFbLock);
            disp = gJobDisplay;
            relMem = gJobMemory;
            relMap = gJobSrcMap;
            startTicks = gJobStartTicks;
            jobFail = gJobMapFailed;
            gJobDisplay = nullptr;
            gJobMemory = nullptr;
            gJobSrcMap = nullptr;
            gJobSrcVa = nullptr;
            gFastFbBusy = false;
            IOLockUnlock(gFastFbLock);

            OSSafeReleaseNULL(relMap);
            OSSafeReleaseNULL(relMem);

            if (!jobFail) {
                __atomic_add_fetch(&violin_fastfb_frames, 1u, __ATOMIC_RELAXED);
                native_legacy_copy_timing_observed(endTicks - startTicks,
                                                   static_cast<uint64_t>(width) * static_cast<uint64_t>(height) * 4ULL);
            } else {
                __atomic_add_fetch(&violin_fastfb_fallbacks, 1u, __ATOMIC_RELAXED);
            }
            native_legacy_gpu_complete(disp, jobFail ? -1 : 0);
        }
    }
}

static void violin_fastfb_init(uint64_t pa, uint64_t len, uint32_t width, uint32_t height)
{
    unsigned en = 1u;
    PE_parse_boot_argn("violin-fast-fb", &en, sizeof(en));
    if (en == 0u) {
        kprintf("[VIOLIN_FASTFB] disabled by boot-arg violin-fast-fb=0\n");
        return;
    }
    unsigned nthr = 4u;
    PE_parse_boot_argn("violin-fast-fb-threads", &nthr, sizeof(nthr));
    if (nthr < 1u) nthr = 1u;
    if (nthr > VIOLIN_FASTFB_MAX_WORKERS) nthr = VIOLIN_FASTFB_MAX_WORKERS;
    /* Source IOSurface is CPU-coherent copyback DRAM; WC stnp + dsb oshst needs no src cache eviction */
    unsigned fl = 0u;
    PE_parse_boot_argn("violin-fast-fb-flush", &fl, sizeof(fl));
    gFastFbFlush = fl;

    if (height == 0u || width == 0u || len < static_cast<uint64_t>(width) * height * 4ULL) {
        return;
    }
    gViolinGopStride = len / static_cast<uint64_t>(height);
    if (gViolinGopStride < static_cast<uint64_t>(width) * 4ULL) {
        return;
    }

    gViolinWcDesc = IOMemoryDescriptor::withPhysicalAddress(
        static_cast<IOPhysicalAddress>(pa), static_cast<IOByteCount>(len), kIODirectionOutIn);
    if (!gViolinWcDesc) {
        kprintf("[VIOLIN_FASTFB] FAIL: withPhysicalAddress(0x%llx, 0x%llx) failed\n",
                static_cast<unsigned long long>(pa), static_cast<unsigned long long>(len));
        return;
    }
    gViolinWcMap = gViolinWcDesc->map(kIOMapAnywhere | kIOMapWriteCombineCache);
    if (!gViolinWcMap || !gViolinWcMap->getVirtualAddress() || gViolinWcMap->getLength() < len) {
        kprintf("[VIOLIN_FASTFB] FAIL: WC map failed map=%p\n", gViolinWcMap);
        OSSafeReleaseNULL(gViolinWcMap);
        OSSafeReleaseNULL(gViolinWcDesc);
        return;
    }
    gViolinWcVa = reinterpret_cast<uint8_t *>(gViolinWcMap->getVirtualAddress());
    gViolinWcBytes = gViolinWcMap->getLength();

    gFastFbLock = IOLockAlloc();
    if (!gFastFbLock) {
        OSSafeReleaseNULL(gViolinWcMap);
        OSSafeReleaseNULL(gViolinWcDesc);
        gViolinWcVa = nullptr;
        return;
    }

    uint32_t started = 0u;
    for (uint32_t i = 0u; i < nthr; ++i) {
        thread_t thr = nullptr;
        if (kernel_thread_start(violin_fastfb_worker,
                                reinterpret_cast<void *>(static_cast<uintptr_t>(i)),
                                &thr) == KERN_SUCCESS) {
            thread_deallocate(thr);
            ++started;
        } else {
            break;
        }
    }
    if (started == 0u) {
        kprintf("[VIOLIN_FASTFB] FAIL: could not start worker threads\n");
        return;
    }
    gFastFbWorkers = started;
    __atomic_store_n(&violin_fastfb_active, 1u, __ATOMIC_RELEASE);
    kprintf("[VIOLIN_FASTFB] PASS: WC pa=0x%llx va=%p bytes=0x%llx stride=%llu workers=%u flush=%u\n",
            static_cast<unsigned long long>(pa), gViolinWcVa,
            static_cast<unsigned long long>(gViolinWcBytes),
            static_cast<unsigned long long>(gViolinGopStride),
            started, gFastFbFlush);
}

static void violin_probe_dsi_tmg_readonly(void)
{
    unsigned isQemu = 0u;
    PE_parse_boot_argn("violin_qemu", &isQemu, sizeof(isQemu));
    if (isQemu != 0u) {
        return;
    }
    IODeviceMemory *mem = IODeviceMemory::withRange(0xE7051200ULL, 0x200ULL);
    if (!mem) {
        return;
    }
    IOMemoryMap *map = mem->map(kIOMapAnywhere | kIOMapInhibitCache);
    mem->release();
    if (!map || !map->getVirtualAddress()) {
        OSSafeReleaseNULL(map);
        return;
    }
    volatile const uint32_t *r = reinterpret_cast<volatile const uint32_t *>(map->getVirtualAddress());
    for (unsigned i = 0u; i < 8u; ++i) {
        violin_dsi_tmg_regs[i] = r[i];
    }
    kprintf("[VIOLIN_DSI_TMG] base=0xE7051200 r00=0x%08x r04=0x%08x r08=0x%08x r0c=0x%08x\n",
            violin_dsi_tmg_regs[0], violin_dsi_tmg_regs[1],
            violin_dsi_tmg_regs[2], violin_dsi_tmg_regs[3]);
    kprintf("[VIOLIN_DSI_TMG2] r10=0x%08x r14=0x%08x r18=0x%08x r1c=0x%08x\n",
            violin_dsi_tmg_regs[4], violin_dsi_tmg_regs[5],
            violin_dsi_tmg_regs[6], violin_dsi_tmg_regs[7]);
    map->release();
}

void native_legacy_default_surface_observed(bool ok, OSObject *surface, uint32_t width, uint32_t height,
                                            uint64_t stride, uint64_t alloc, uint64_t descLen)
{
    __atomic_store_n(&violin_legacy_default_surface_ok, ok ? 1u : 0u, __ATOMIC_RELEASE);
    kprintf("[VIOLIN_LEGACY] default_surface ok=%u surf=%p mode=%ux%u stride=%llu alloc=%llu desc=%llu\n",
            ok ? 1u : 0u, surface, width, height,
            static_cast<unsigned long long>(stride),
            static_cast<unsigned long long>(alloc),
            static_cast<unsigned long long>(descLen));
}

__attribute__((noreturn)) void native_legacy_backend_guard(unsigned slot, void *self, void *caller)
{
    kprintf("[VIOLIN_LEGACY] GUARD_TRAP slot=%u self=%p caller=%p\n", slot, self, caller);
    panic("violin: NativeLegacyDisplay unclassified backend leaf slot=%u caller=%p", slot, caller);
}

bool native_legacy_gop_mapping_observed(IOService *display, IOMemoryMap *map, uint32_t width, uint32_t height)
{
    uint64_t pa = map ? static_cast<uint64_t>(map->getPhysicalAddress()) : 0ULL;
    uint64_t va = map ? static_cast<uint64_t>(map->getVirtualAddress()) : 0ULL;
    uint64_t len = map ? static_cast<uint64_t>(map->getLength()) : 0ULL;
    violin_legacy_stage = 5;
    if (va != 0ULL && len != 0ULL && width > 0u && height > 0u) {
        gViolinGopFb = reinterpret_cast<volatile uint32_t *>(va);
        gViolinGopWidth = width;
        gViolinGopHeight = height;
        gViolinGopBytes = len;
        violin_fastfb_init(pa, len, width, height);
        violin_probe_dsi_tmg_readonly();
    }
    kprintf("[VIOLIN_LEGACY] gop_mapping display=%p pa=0x%llx va=0x%llx bytes=0x%llx mode=%ux%u\n",
            display,
            static_cast<unsigned long long>(pa),
            static_cast<unsigned long long>(va),
            static_cast<unsigned long long>(len),
            width, height);
    return map != nullptr && va != 0ULL && pa != 0ULL && len != 0ULL;
}

void native_legacy_registration_observed(IOService *display)
{
    violin_legacy_stage = 8;
    kprintf("[VIOLIN_LEGACY] registerService ok display=%p\n", display);
}

void native_legacy_pm_observed(unsigned stage, IOReturn status, unsigned long ordinal)
{
    if (stage == 4u && status == kIOReturnSuccess && ordinal == 1ul) {
        __atomic_store_n(&violin_legacy_pm_ready, 1u, __ATOMIC_RELEASE);
    }
    kprintf("[VIOLIN_LEGACY] pm stage=%u status=0x%x ordinal=%lu\n",
            stage, static_cast<unsigned>(status), ordinal);
}

void native_legacy_client_enter(task_t task, uint32_t type)
{
    uint32_t c = __atomic_add_fetch(&violin_legacy_clients, 1u, __ATOMIC_RELAXED);
    kprintf("[VIOLIN_LEGACY] client_enter #%u task=%p type=%u\n", c, task, type);
}

void native_legacy_client_observed(IOReturn status, IOUserClient *client)
{
    violin_legacy_stage = 10;
    kprintf("[VIOLIN_LEGACY] client_observed status=0x%x client=%p class=%s\n",
            static_cast<unsigned>(status),
            client,
            (client && client->getMetaClass()) ? client->getMetaClass()->getClassName() : "<null>");
}

void native_legacy_swap_stage(unsigned stage)
{
    (void)stage;
}

void native_legacy_swap_validation_observed(bool accepted, unsigned reason, const void *req, const void *surf)
{
    uint32_t n = __atomic_add_fetch(&violin_legacy_validations, 1u, __ATOMIC_RELAXED);
    if (!accepted) {
        __atomic_add_fetch(&violin_legacy_rejected, 1u, __ATOMIC_RELAXED);
    }
    if (n <= 12u || (!accepted && violin_legacy_rejected <= 16u)) {
        kprintf("[VIOLIN_LEGACY] validate #%u ok=%u reason=%u req=%p surf=%p\n",
                n, accepted ? 1u : 0u, reason, req, surf);
    }
}

void native_legacy_surface_rejected(uint64_t w, uint64_t h, uint32_t fmt, uint32_t planes,
                                    uint64_t stride, uint64_t alloc, uint64_t len)
{
    kprintf("[VIOLIN_LEGACY] surface_rejected %llux%llu fmt=0x%x planes=%u stride=%llu alloc=%llu len=%llu\n",
            static_cast<unsigned long long>(w), static_cast<unsigned long long>(h),
            fmt, planes,
            static_cast<unsigned long long>(stride),
            static_cast<unsigned long long>(alloc),
            static_cast<unsigned long long>(len));
}

bool native_legacy_prepare_scanout(void)
{
    return true;
}

void native_legacy_transfer_observed(IOReturn status, const void *req, uint64_t bytes)
{
    uint32_t n = __atomic_add_fetch(&violin_legacy_transfers, 1u, __ATOMIC_RELAXED);
    if (n <= 12u || status != kIOReturnSuccess) {
        kprintf("[VIOLIN_LEGACY] transfer #%u status=0x%x req=%p bytes=%llu\n",
                n, static_cast<unsigned>(status), req, static_cast<unsigned long long>(bytes));
    }
}

void native_legacy_copy_timing_observed(uint64_t ticks, uint64_t bytes)
{
    uint64_t freq = 0;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    if (freq == 0ULL) {
        freq = 38400000ULL;
    }
    uint64_t us = (ticks * 1000000ULL) / freq;
    violin_legacy_last_copy_us = us;
    uint32_t cnt = __atomic_add_fetch(&violin_legacy_copy_count, 1u, __ATOMIC_RELAXED);
    if (us < violin_legacy_copy_min_us) violin_legacy_copy_min_us = us;
    if (us > violin_legacy_copy_max_us) violin_legacy_copy_max_us = us;
    violin_legacy_copy_sum_us += us;
    if (cnt <= 12u || (cnt % 60u) == 0u || us > 20000ULL) {
        uint64_t avg = violin_legacy_copy_sum_us / cnt;
        kprintf("[VIOLIN_LEGACY] copy_timing #%u us=%llu avg=%llu min=%llu max=%llu bytes=%llu fast=%u\n",
                cnt,
                static_cast<unsigned long long>(us),
                static_cast<unsigned long long>(avg),
                static_cast<unsigned long long>(violin_legacy_copy_min_us),
                static_cast<unsigned long long>(violin_legacy_copy_max_us),
                static_cast<unsigned long long>(bytes),
                violin_fastfb_active);
    }
}

void native_legacy_retirement_observed(IOService *display)
{
    uint32_t n = __atomic_add_fetch(&violin_legacy_retirements, 1u, __ATOMIC_RELAXED);
    if (n <= 12u || n == 20u || n == 40u || (n % 120u) == 0u) {
        uint32_t p0 = 0, p1 = 0, p2 = 0, p3 = 0;
        if (gViolinGopFb != nullptr && gViolinGopWidth > 0u && gViolinGopHeight > 0u) {
            uint64_t rowPx = gViolinGopBytes / (4ULL * gViolinGopHeight);
            if (rowPx >= gViolinGopWidth) {
                p0 = gViolinGopFb[(gViolinGopHeight / 4u) * rowPx + (gViolinGopWidth / 4u)];
                p1 = gViolinGopFb[(gViolinGopHeight / 2u) * rowPx + (gViolinGopWidth / 2u)];
                p2 = gViolinGopFb[(gViolinGopHeight * 3u / 4u) * rowPx + (gViolinGopWidth * 3u / 4u)];
                p3 = gViolinGopFb[(gViolinGopHeight - 16u) * rowPx + (gViolinGopWidth / 2u)];
            }
        }
        kprintf("[VIOLIN_LEGACY] retire #%u display=%p stats(val=%u,kick=%u,copy=%u,ret=%u) px=(0x%08x,0x%08x,0x%08x,0x%08x)\n",
                n, display,
                native_legacy_swapstat[0], native_legacy_swapstat[1],
                native_legacy_swapstat[7], native_legacy_swapstat[11],
                p0, p1, p2, p3);
    }
}

void native_legacy_frame_observed(unsigned kind, uint64_t count, uint64_t minx, uint64_t miny,
                                  uint64_t maxx, uint64_t maxy)
{
    (void)kind; (void)count; (void)minx; (void)miny; (void)maxx; (void)maxy;
}

void native_legacy_frame_colors_observed(const uint32_t *colors, const uint64_t *counts, uint64_t other)
{
    (void)colors; (void)counts; (void)other;
}

bool native_legacy_gpu_offer(void *display, IOMemoryDescriptor *memory, uint64_t stride,
                             uint32_t width, uint32_t height, uint32_t format)
{
    /* NGP_BGRX8888 == 1 (NativeGOPWire.h). Fall back cleanly for half-float or inactive WC. */
    if (__atomic_load_n(&violin_fastfb_active, __ATOMIC_ACQUIRE) == 0u ||
        format != 1u || display == nullptr || memory == nullptr || gViolinWcVa == nullptr) {
        return false;
    }
    if (!violin_fastfb_validate(width, height, stride, memory->getLength(),
                                gViolinGopStride, gViolinWcBytes)) {
        return false;
    }
    memory->retain();
    IOLockLock(gFastFbLock);
    if (gFastFbBusy || gFastFbWorkers == 0u) {
        IOLockUnlock(gFastFbLock);
        memory->release();
        return false;
    }
    gJobDisplay = display;
    gJobMemory = memory;
    gJobSrcStride = stride;
    gJobWidth = width;
    gJobHeight = height;
    gJobStartTicks = readCntpct();
    gJobSrcMap = nullptr;
    gJobSrcVa = nullptr;
    gJobMapFailed = false;
    gFastFbRemaining = gFastFbWorkers;
    gFastFbBusy = true;
    ++gFastFbGen;
    IOLockWakeup(gFastFbLock, &gFastFbGen, false);
    IOLockUnlock(gFastFbLock);
    return true;
}

void native_legacy_gpu_fallback_observed(int status)
{
    __atomic_add_fetch(&violin_fastfb_fallbacks, 1u, __ATOMIC_RELAXED);
    kprintf("[VIOLIN_LEGACY] gpu_fallback status=%d\n", status);
}

void native_legacy_vsync_observed(unsigned event, unsigned hz)
{
    if (event == 1u) {
        uint32_t n = __atomic_add_fetch(&violin_legacy_vsync_ticks, 1u, __ATOMIC_RELAXED);
        if (n <= 5u || (n % 240u) == 0u) {
            kprintf("[VIOLIN_LEGACY] vsync tick #%u hz=%u\n", n, hz);
        }
    } else if (event == 0u || event == 4u || event == 5u) {
        kprintf("[VIOLIN_LEGACY] vsync event=%u hz=%u\n", event, hz);
    }
}

void violin_legacy_display_init(IOService *nub)
{
    if (gViolinLegacyDisplay != nullptr || nub == nullptr) {
        return;
    }

    unsigned int enabled = 0;
    if (!PE_parse_boot_argn("offline-legacy-gop", &enabled, sizeof(enabled)) || enabled != 1u) {
        return;
    }

    violin_legacy_stage = 1;
    OSReturn surfRc = OSKextLoadKextWithIdentifier("com.apple.iokit.IOSurface");
    OSReturn gfxRc = OSKextLoadKextWithIdentifier("com.apple.iokit.IOMobileGraphicsFamily");
    kprintf("[VIOLIN_LEGACY] kext_load IOSurface=0x%x IOMobileGraphicsFamily=0x%x\n",
            static_cast<unsigned>(surfRc), static_cast<unsigned>(gfxRc));
    if (gfxRc != kOSReturnSuccess) {
        kprintf("[VIOLIN_LEGACY] FAIL: IOMobileGraphicsFamily load failed rc=0x%x\n",
                static_cast<unsigned>(gfxRc));
        return;
    }

    /* Ensure IOSurfaceRoot has matched IOBSD before IOMobileFramebufferLegacy::start queries it. */
    IOService *surfRoot = nullptr;
    OSDictionary *matchDict = IOService::serviceMatching("IOSurfaceRoot");
    if (matchDict != nullptr) {
        surfRoot = IOService::waitForMatchingService(matchDict, 3000000000ULL);
        matchDict->release();
    }
    kprintf("[VIOLIN_LEGACY] IOSurfaceRoot=%p\n", surfRoot);
    if (surfRoot != nullptr) {
        surfRoot->release();
    }

    violin_legacy_stage = 2;
    void *loadHandle = OSMetaClass::preModLoad("com.apple.iokit.IOMobileGraphicsFamily");
    if (loadHandle == nullptr) {
        kprintf("[VIOLIN_LEGACY] FAIL: OSMetaClass::preModLoad returned NULL\n");
        return;
    }
    native_legacy_display_static_init();
    OSReturn postRc = OSMetaClass::postModLoad(loadHandle);
    kprintf("[VIOLIN_LEGACY] metaclass postModLoad rc=0x%x\n", static_cast<unsigned>(postRc));
    if (postRc != kOSReturnSuccess) {
        kprintf("[VIOLIN_LEGACY] FAIL: OSMetaClass::postModLoad failed\n");
        return;
    }

    violin_legacy_stage = 3;
    IOService *disp = native_legacy_display_allocate();
    if (disp == nullptr) {
        kprintf("[VIOLIN_LEGACY] FAIL: native_legacy_display_allocate returned NULL\n");
        return;
    }
    const OSMetaClass *mc = disp->getMetaClass();
    const OSMetaClass *superMc = mc ? mc->getSuperClass() : nullptr;
    kprintf("[VIOLIN_LEGACY] alloc disp=%p class=%s size=%u super=%s\n",
            disp,
            mc ? mc->getClassName() : "<null>",
            mc ? mc->getClassSize() : 0u,
            superMc ? superMc->getClassName() : "<null>");

    if (!disp->init()) {
        kprintf("[VIOLIN_LEGACY] FAIL: NativeLegacyDisplay::init() returned false\n");
        disp->release();
        return;
    }
    violin_legacy_stage = 4;
    if (!disp->attach(nub)) {
        kprintf("[VIOLIN_LEGACY] FAIL: NativeLegacyDisplay::attach(nub) returned false\n");
        disp->release();
        return;
    }
    bool started = disp->start(nub);
    kprintf("[VIOLIN_LEGACY] start=%u stage=%u\n", started ? 1u : 0u, violin_legacy_stage);
    if (!started) {
        disp->detach(nub);
        disp->release();
        return;
    }

    IOPMrootDomain *rootPm = IOService::getPMRootDomain();
    IOPlatformExpert *pe = IOService::getPlatform();
    const uint8_t *rawDisp = reinterpret_cast<const uint8_t *>(disp);
    bool addedRoot = false;
    for (unsigned waitMs = 0; waitMs < 500u; waitMs += 10u) {
        if (__atomic_load_n(&violin_legacy_pm_ready, __ATOMIC_ACQUIRE) != 0u) {
            break;
        }
        if (waitMs == 50u && !addedRoot && rootPm != nullptr && !disp->inPlane(gIOPowerPlane)) {
            IOReturn addRc = rootPm->addPowerChild(disp);
            kprintf("[VIOLIN_LEGACY] pm_attach_root rootPm=%p pe=%s addRc=0x%x\n",
                    rootPm,
                    (pe && pe->getMetaClass()) ? pe->getMetaClass()->getClassName() : "<null>",
                    static_cast<unsigned>(addRc));
            addedRoot = true;
        }
        IOSleep(10);
    }
    uint32_t stateEn = 0, statePwr = 0;
    memcpy(&stateEn, rawDisp + 7180u, sizeof(stateEn));
    memcpy(&statePwr, rawDisp + 7184u, sizeof(statePwr));
    kprintf("[VIOLIN_LEGACY] pm_settled ready=%u inPlane=%u state=(en=%u,pwr=%u) pe=%s\n",
            __atomic_load_n(&violin_legacy_pm_ready, __ATOMIC_ACQUIRE),
            disp->inPlane(gIOPowerPlane) ? 1u : 0u,
            stateEn, statePwr,
            (pe && pe->getMetaClass()) ? pe->getMetaClass()->getClassName() : "<null>");

    gViolinLegacyDisplay = disp;
    kprintf("[VIOLIN_LEGACY] PASS: NativeLegacyDisplay active on display-subsystem (%p)\n", disp);
}
}
