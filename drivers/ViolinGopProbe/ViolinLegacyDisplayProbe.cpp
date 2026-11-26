// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * ViolinLegacyDisplayProbe — Stage-7 Phase-7B board probe for NativeLegacyDisplay.
 *
 * Deferred kext loader + OSMetaClass registration + telemetry callbacks for
 * upstream NativeLegacyDisplay.cpp bound against 24A446 IOMobileGraphicsFamily
 * and IOSurface (zero edits to source/UniXNU).
 */

#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <libkern/OSKextLib.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSMetaClass.h>
#include <pexpert/pexpert.h>

extern "C" {
void kprintf(const char *fmt, ...);

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

static IOService *gViolinLegacyDisplay = nullptr;
static volatile uint32_t *gViolinGopFb = nullptr;
static uint32_t gViolinGopWidth = 0;
static uint32_t gViolinGopHeight = 0;
static uint64_t gViolinGopBytes = 0;

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
    kprintf("[VIOLIN_LEGACY] copy_timing ticks=%llu us=%llu bytes=%llu\n",
            static_cast<unsigned long long>(ticks),
            static_cast<unsigned long long>(us),
            static_cast<unsigned long long>(bytes));
}

void native_legacy_retirement_observed(IOService *display)
{
    uint32_t n = __atomic_add_fetch(&violin_legacy_retirements, 1u, __ATOMIC_RELAXED);
    if (n <= 12u || n == 20u || n == 40u || (n % 60u) == 0u) {
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
    (void)kind;
    (void)count;
    (void)minx;
    (void)miny;
    (void)maxx;
    (void)maxy;
}

void native_legacy_frame_colors_observed(const uint32_t *colors, const uint64_t *counts, uint64_t other)
{
    (void)colors;
    (void)counts;
    (void)other;
}

bool native_legacy_gpu_offer(void *display, IOMemoryDescriptor *memory, uint64_t stride,
                             uint32_t width, uint32_t height, uint32_t format)
{
    (void)display;
    (void)memory;
    (void)stride;
    (void)width;
    (void)height;
    (void)format;
    return false;
}

void native_legacy_gpu_fallback_observed(int status)
{
    kprintf("[VIOLIN_LEGACY] gpu_fallback status=%d\n", status);
}

void native_legacy_vsync_observed(unsigned event, unsigned hz)
{
    if (event == 1u) {
        uint32_t n = __atomic_add_fetch(&violin_legacy_vsync_ticks, 1u, __ATOMIC_RELAXED);
        if (n <= 5u || (n % 60u) == 0u) {
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

    /* Wait for IOKit PM (setPowerState(1) -> IOMFB state[+0x1c0c]=1) to settle before EL0 runs.
     * If platform PMRegisterDevice did not link display-subsystem into gIOPowerPlane, attach
     * directly under IOPMrootDomain as IOPlatformExpert::PMRegisterDevice does by default. */
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
