// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * ViolinGopProbe — Stage-7 Phase-7A board bootstrap for NativeGOPPresenter.
 *
 * Dynamically queries PE_current_console(&video) so the exact same kernel works on:
 *   - Live Xiaomi Pad 7S Pro (violin / O81A): 3200x2136 BGRX32 @ 0x29BFF000 (308 dpi)
 *   - QEMU virt (ViolinGopDxe QEMU_TEST=1):   1280x800  BGRX32 @ 0x17F810000 (144 dpi)
 *
 * Creates a dynamic "display-subsystem" IOService nub with IODeviceMemory[0] and
 * dot-pitch, attaches upstream NativeGOPPresenter (zero edits to source/UniXNU),
 * and exposes NativeGOPClient to EL0.
 */

#include <IOKit/IODeviceMemory.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOService.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSData.h>
#include <pexpert/pexpert.h>

extern "C" {
void kprintf(const char *fmt, ...);
IOService *native_gop_presenter_create(void);
void native_gop_presenter_set_source(IOService *presenter, IOService *nub);
extern volatile uint32_t native_gop_ready;
extern volatile uint64_t native_gop_physical;
extern volatile uint64_t native_gop_virtual;

/* Phase-7A operates with fb-gpu=0 (no NativeLegacyDisplay linked yet). */
void native_legacy_gpu_complete(void *display, int status) __attribute__((weak));
void native_legacy_gpu_complete(void *display, int status)
{
    (void)display;
    (void)status;
}

/* Phase-7B optional hook overridden strongly by ViolinLegacyDisplayProbe.cpp. */
void violin_legacy_display_init(IOService *nub) __attribute__((weak));
void violin_legacy_display_init(IOService *nub)
{
    (void)nub;
}

/* Stage-7F optional hook overridden strongly by XringBacklight.cpp. */
void violin_backlight_init(IOService *nub) __attribute__((weak));
void violin_backlight_init(IOService *nub)
{
    (void)nub;
}

void violin_gop_presenter_init(void);
}

static IOService *gViolinDisplayNub = nullptr;
static IOService *gViolinGopPresenter = nullptr;

extern "C" void violin_gop_presenter_init(void)
{
    if (gViolinDisplayNub != nullptr || gViolinGopPresenter != nullptr) {
        return;
    }

    unsigned int presenterEnabled = 0;
    unsigned int legacyEnabled = 0;
    PE_parse_boot_argn("violin-gop-presenter", &presenterEnabled, sizeof(presenterEnabled));
    PE_parse_boot_argn("offline-legacy-gop", &legacyEnabled, sizeof(legacyEnabled));
    if (presenterEnabled == 0u && legacyEnabled == 0u) {
        return;
    }

    PE_Video video = {};
    if (PE_current_console(&video) != 0 ||
        video.v_baseAddr == 0 || video.v_width == 0 || video.v_height == 0 ||
        video.v_depth != 32 || video.v_rowBytes < video.v_width * 4) {
        kprintf("[VIOLIN_GOP] FAIL: invalid PE_current_console base=0x%lx w=%lu h=%lu row=%lu depth=%lu\n",
                video.v_baseAddr, video.v_width, video.v_height, video.v_rowBytes, video.v_depth);
        return;
    }

    uint64_t fbBytes = static_cast<uint64_t>(video.v_rowBytes) * static_cast<uint64_t>(video.v_height);
    kprintf("[VIOLIN_GOP] pe_video base=0x%llx w=%lu h=%lu row=%lu depth=%lu disp=%lu bytes=0x%llx\n",
            static_cast<unsigned long long>(video.v_baseAddr),
            video.v_width, video.v_height, video.v_rowBytes, video.v_depth, video.v_display,
            static_cast<unsigned long long>(fbBytes));

    IOService *parent = nullptr;
    IORegistryEntry *armIo = IORegistryEntry::fromPath("/arm-io", gIODTPlane);
    if (armIo != nullptr) {
        parent = OSDynamicCast(IOService, armIo);
        if (parent == nullptr) {
            armIo->release();
        }
    }
    if (parent == nullptr) {
        parent = IOService::getPlatform();
        if (parent != nullptr) {
            parent->retain();
        }
    }
    if (parent == nullptr) {
        kprintf("[VIOLIN_GOP] FAIL: no parent IOService for display-subsystem\n");
        return;
    }

    IOService *nub = new IOService;
    if (nub == nullptr || !nub->init()) {
        if (nub != nullptr) nub->release();
        parent->release();
        kprintf("[VIOLIN_GOP] FAIL: nub alloc/init failed\n");
        return;
    }
    nub->setName("display-subsystem");
    nub->setProperty("compatible", "violin,gop-display");

    uint32_t dotPitch = 216u;
    if (video.v_width == 3200 && video.v_height == 2136) {
        dotPitch = 308u; /* O81A 12.50" 264.0mm x 176.2mm */
    } else if (video.v_width == 1280 && video.v_height == 800) {
        dotPitch = 144u; /* QEMU virt synthetic panel */
    }
    OSData *dpData = OSData::withBytes(&dotPitch, sizeof(dotPitch));
    if (dpData != nullptr) {
        nub->setProperty("dot-pitch", dpData);
        dpData->release();
    }

    IODeviceMemory *fbMem = IODeviceMemory::withRange(
        static_cast<IOPhysicalAddress>(video.v_baseAddr),
        static_cast<IOByteCount>(fbBytes));
    if (fbMem == nullptr) {
        nub->release();
        parent->release();
        kprintf("[VIOLIN_GOP] FAIL: IODeviceMemory::withRange failed\n");
        return;
    }
    OSObject *memObjs[1] = { fbMem };
    OSArray *memArray = OSArray::withObjects(const_cast<const OSObject **>(memObjs), 1u);
    fbMem->release();
    if (memArray == nullptr) {
        nub->release();
        parent->release();
        kprintf("[VIOLIN_GOP] FAIL: OSArray::withObjects failed\n");
        return;
    }
    nub->setDeviceMemory(memArray);
    memArray->release();

    if (!nub->attach(parent) || !nub->start(parent)) {
        nub->detach(parent);
        nub->release();
        parent->release();
        kprintf("[VIOLIN_GOP] FAIL: nub attach/start failed\n");
        return;
    }
    gViolinDisplayNub = nub;

    if (presenterEnabled != 0u) {
        IOService *presenter = native_gop_presenter_create();
        if (presenter == nullptr || !presenter->init()) {
            if (presenter != nullptr) presenter->release();
            kprintf("[VIOLIN_GOP] FAIL: NativeGOPPresenter create/init failed\n");
        } else {
            /* Attach presenter away from display-subsystem so IOMobileFramebufferLegacy
             * sees only clean children on display-subsystem while sharing IODeviceMemory[0]. */
            native_gop_presenter_set_source(presenter, nub);
            if (!presenter->attach(parent) || !presenter->start(parent)) {
                presenter->detach(parent);
                presenter->release();
                kprintf("[VIOLIN_GOP] FAIL: NativeGOPPresenter attach/start failed\n");
            } else {
                gViolinGopPresenter = presenter;
                kprintf("[VIOLIN_GOP] presenter=ready ready=%u pa=0x%llx va=0x%llx dot_pitch=%u\n",
                        native_gop_ready,
                        static_cast<unsigned long long>(native_gop_physical),
                        static_cast<unsigned long long>(native_gop_virtual),
                        dotPitch);
            }
        }
    }
    parent->release();

    if (legacyEnabled != 0u) {
        violin_legacy_display_init(nub);
    }

    violin_backlight_init(nub);
}
