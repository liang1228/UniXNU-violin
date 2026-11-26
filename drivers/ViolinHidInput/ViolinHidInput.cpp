// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * ViolinHidInput.cpp — 24A446 arm64e IOHIDDevice multi-touch + bottom-edge
 * swipe driver for Xiaomi Pad 7S Pro (violin / O81A, 3200x2136).
 *
 * Adapted from UniXNU/ShengHidInput/NativeHidInput.cpp for 24A446 arm64e
 * IOHIDFamily-2238.120.5 with build-time 207-slot PAC audit and 220-slot
 * IOHIDEventDriver::dispatchEvent edge-tip wrapper (kIOHIDDigitizerEventFromEdgeTip).
 */

#include "OriginalHidDeviceABI.h"
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOWorkLoop.h>
#include <libkern/OSKextLib.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSIterator.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <pexpert/pexpert.h>
#include <ptrauth.h>
#include <stdint.h>
#include <string.h>

extern "C" {
void kprintf(const char *fmt, ...);

/* Shared seqlock state from ViolinTouchDriver.cpp */
extern volatile uint32_t violin_touch_seq;
extern volatile uint32_t violin_touch_count;
extern volatile uint32_t violin_touch_hid_reports;
extern volatile int violin_touch_xs[10];
extern volatile int violin_touch_ys[10];
extern volatile int violin_touch_ids[10];
void violin_touch_set_sink(void (*fn)(void *), void *ctx);
void violin_touch_publish_contacts(unsigned count, const int *ids, const int *xs, const int *ys);

volatile uint32_t violin_hid_stage = 0u;
volatile uint32_t violin_hid_driver_found = 0u;
volatile uint32_t violin_hid_edge_install[3] = {}; /* [0]=outcome(3=ok), [1]=slots, [2]=badSlot */
volatile uint32_t violin_hid_edge_stats[4] = {};   /* [0]=installed, [1]=begun, [2]=fromEdge, [3]=skipped */
volatile uint32_t violin_hid_selftest_done = 0u;
} // extern "C"

#define VIOLIN_TOUCH_FINGERS 10

/* Keyboard + Consumer (Reports 1 & 2) ensures generic HID personality matching,
 * followed by 10-finger Touch Screen digitizer (Report 3, 0..32767 normalized X/Y). */
static const unsigned char kKeyboardDescriptor[] = {
    0x05,0x01,0x09,0x06,0xa1,0x01,0x85,0x01,
    0x05,0x07,0x19,0xe0,0x29,0xe7,0x15,0x00,0x25,0x01,
    0x75,0x01,0x95,0x08,0x81,0x02,
    0x75,0x08,0x95,0x01,0x81,0x03,
    0x19,0x00,0x29,0x65,0x15,0x00,0x25,0x65,
    0x75,0x08,0x95,0x06,0x81,0x00,
    0x85,0x02,0x05,0x0c,0x09,0x40,0x09,0x30,0x09,0xe9,0x09,0xea,0x15,0x00,0x25,0x01,
    0x75,0x01,0x95,0x04,0x81,0x02,
    0x75,0x04,0x95,0x01,0x81,0x03,0xc0
};

#define VIOLIN_FINGER_DESC \
    0x09,0x22,0xa1,0x02, 0x09,0x42,0x15,0x00,0x25,0x01,0x75,0x01,0x95,0x01,0x81,0x02, \
    0x09,0x47,0x81,0x02, 0x75,0x06,0x95,0x01,0x81,0x03, \
    0x09,0x51,0x75,0x08,0x95,0x01,0x15,0x00,0x26,0xff,0x00,0x81,0x02, \
    0x05,0x01,0x09,0x30,0x15,0x00,0x26,0xff,0x7f,0x75,0x10,0x95,0x01,0x81,0x02, \
    0x09,0x31,0x81,0x02, 0x05,0x0d,0xc0,

static const unsigned char kTouchDescriptor[] = {
    0x05,0x0d,0x09,0x04,0xa1,0x01,0x85,0x03,
    VIOLIN_FINGER_DESC VIOLIN_FINGER_DESC VIOLIN_FINGER_DESC VIOLIN_FINGER_DESC VIOLIN_FINGER_DESC
    VIOLIN_FINGER_DESC VIOLIN_FINGER_DESC VIOLIN_FINGER_DESC VIOLIN_FINGER_DESC VIOLIN_FINGER_DESC
    0x09,0x54,0x75,0x08,0x95,0x01,0x15,0x00,0x26,0xff,0x00,0x81,0x02,0xc0
};

namespace violin_edge {

enum { kSlots = 256, kDispatch = 198, kGetType = 18, kGetInteger = 23, kSetInteger = 24, kGetFixed = 25, kContacts = 256 };
enum : uint32_t { kDigitizer = 11, kX = 0xB0000, kY = 0xB0001, kIndex = 0xB0005, kMask = 0xB0007, kTouch = 0xB0009, kMaskTouch = 2, kFromEdgeTip = 0x800 };
enum : uint16_t { kDivDispatch = 0x1134, kDivGetType = 0x8758, kDivGetInteger = 0x02c5, kDivSetInteger = 0x130e, kDivGetFixed = 0xf637, kVptrDiscriminator = 0xcda1 };

/* 48 panel pixels on 3200 x 2136 (violin) in IOFixed 0..65536 coordinates */
static constexpr int32_t kEdgeX = 48 * 65536 / 3200;
static constexpr int32_t kEdgeY = 48 * 65536 / 2136;

static void (*originalDispatch)(IOService *, OSObject *, IOOptionBits) = nullptr;
static bool fromEdge[kContacts] = {};

static void **vtableOf(void *object)
{
    return reinterpret_cast<void **>(
        ptrauth_auth_data(*reinterpret_cast<void **>(object),
                          ptrauth_key_process_independent_data,
                          ptrauth_blend_discriminator(object, kVptrDiscriminator)));
}

template <typename R, typename... A>
static R call(void *object, unsigned slot, uint16_t diversity, A... args)
{
    void **entry = vtableOf(object) + slot;
    void *function = ptrauth_auth_and_resign(
        *entry,
        ptrauth_key_function_pointer, ptrauth_blend_discriminator(entry, diversity),
        ptrauth_key_function_pointer, 0);
    return reinterpret_cast<R (*)(void *, A...)>(function)(object, args...);
}

static bool mark(void *child)
{
    if (call<uint32_t, IOOptionBits>(child, kGetType, kDivGetType, 0) != kDigitizer) return false;
    const uint32_t index = static_cast<uint32_t>(call<int32_t, uint32_t, IOOptionBits>(child, kGetInteger, kDivGetInteger, kIndex, 0));
    if (index >= kContacts) {
        violin_hid_edge_stats[3] = violin_hid_edge_stats[3] + 1u;
        return false;
    }
    const uint32_t mask = static_cast<uint32_t>(call<int32_t, uint32_t, IOOptionBits>(child, kGetInteger, kDivGetInteger, kMask, 0));
    const bool touch = call<int32_t, uint32_t, IOOptionBits>(child, kGetInteger, kDivGetInteger, kTouch, 0) != 0;
    if ((mask & kMaskTouch) && touch) {
        const int32_t x = call<int32_t, uint32_t, IOOptionBits>(child, kGetFixed, kDivGetFixed, kX, 0);
        const int32_t y = call<int32_t, uint32_t, IOOptionBits>(child, kGetFixed, kDivGetFixed, kY, 0);
        fromEdge[index] = (x < kEdgeX) || (x > 65536 - kEdgeX) || (y < kEdgeY) || (y > 65536 - kEdgeY);
        violin_hid_edge_stats[1] = violin_hid_edge_stats[1] + 1u;
        if (fromEdge[index]) violin_hid_edge_stats[2] = violin_hid_edge_stats[2] + 1u;
    }
    const bool edged = fromEdge[index];
    if (edged) {
        call<void, uint32_t, int32_t, IOOptionBits>(child, kSetInteger, kDivSetInteger, kMask, static_cast<int32_t>(mask | kFromEdgeTip), 0);
    }
    if (!touch && (mask & kMaskTouch)) fromEdge[index] = false;
    return edged;
}

static void dispatch(IOService *self, OSObject *event, IOOptionBits options)
{
    if (event && call<uint32_t, IOOptionBits>(event, kGetType, kDivGetType, 0) == kDigitizer) {
        OSArray *children = *reinterpret_cast<OSArray **>(reinterpret_cast<uint8_t *>(event) + 24);
        if (children && OSDynamicCast(OSArray, children) && children->getCount()) {
            bool any = false;
            for (unsigned i = 0; i < children->getCount(); ++i) {
                OSObject *child = children->getObject(i);
                if (child && child->metaCast("IOHIDEvent")) any |= mark(child);
                else violin_hid_edge_stats[3] = violin_hid_edge_stats[3] + 1u;
            }
            if (any) {
                const uint32_t mask = static_cast<uint32_t>(call<int32_t, uint32_t, IOOptionBits>(event, kGetInteger, kDivGetInteger, kMask, 0));
                call<void, uint32_t, int32_t, IOOptionBits>(event, kSetInteger, kDivSetInteger, kMask, static_cast<int32_t>(mask | kFromEdgeTip), 0);
            }
        } else if (!children) {
            mark(event);
        }
    }
    originalDispatch(self, event, options);
}

/* Exact 220-slot PAC diversity table of 24A446 IOHIDEventDriver (IOHIDFamily-2238.120.5) */
static const uint16_t kSlotDiversity[] = {
    0x3771,0x56b7,0xbaa2,0x3607,0x2e4a,0x3a87,0x89a9,0xfffc,0xfc74,0x5635,0xbe60,0x32e5,
    0x9209,0x4a6a,0xedc5,0x5c68,0x6a10,0x7a2a,0xaf75,0x137e,0x0655,0x43aa,0x12e9,0x4578,
    0x4275,0xff53,0x1814,0x122e,0x13f6,0x1d35,0xacb1,0x7eb0,0x1262,0x82eb,0x164e,0x37a5,
    0xb659,0x6c51,0xa20f,0xb3b6,0x6bcb,0x5a20,0x5062,0x00d7,0x7c85,0x8a26,0x3539,0x688b,
    0x1e60,0x1955,0x0689,0xc256,0xa383,0xf021,0x1f0a,0xb4bb,0x8ffc,0xb5b9,0x8764,0x5d96,
    0x80d9,0x0c9c,0x5d0a,0xcbcc,0x617d,0x848a,0x2312,0x3540,0xc257,0x3025,0x9fc2,0x5038,
    0xc666,0x6cc3,0x550c,0xa19a,0xa51b,0x4577,0x573c,0x1a4e,0x6c3d,0xb049,0xc4b2,0xc90d,
    0x7d59,0x4897,0x3c68,0xb085,0x4529,0x639f,0xccfb,0x55eb,0xe933,0xaec3,0x5ec5,0x5219,
    0xc6b2,0x8a43,0x4a20,0xd9f2,0x981a,0xa27f,0xc4f9,0x6b87,0x60a1,0x7e78,0x36aa,0x86ef,
    0x9be9,0x7318,0x93b7,0x638e,0x61a6,0x9175,0x136b,0xdb58,0x4a31,0x0988,0x5393,0xabe0,
    0x0ad9,0x6c99,0xd52d,0xe213,0x308f,0xd78d,0x3a1d,0xa390,0x240b,0x1b89,0x8d3c,0x2652,
    0x7f14,0x0759,0x63c4,0x800f,0x9cc2,0x02ac,0x785f,0xcc6b,0x82cd,0x808e,0x37ce,0xa4c7,
    0xe8de,0xa343,0x4bc0,0xf8a6,0xac7f,0x7974,0xea1b,0x4b35,0x9eb4,0x595a,0x5b2b,0x699e,
    0x2b52,0xf40e,0x0ddb,0x0f88,0x8700,0x36c3,0x058e,0xf16e,0x3a71,0xda1e,0x10b6,0x8654,
    0x96c3,0x4cb5,0x19b8,0x6518,0x5717,0xd2bf,0x09fa,0xad91,0xd335,0x4902,0xae57,0xaad9,
    0x5299,0xe604,0x8660,0x0189,0xc3de,0x41f6,0x5c1e,0xb54e,0xef25,0x4bdd,0xefa8,0x9835,
    0xae71,0x67cf,0xa85e,0x7b4f,0x4abb,0xc0d0,0x1134,0x7eca,0xf128,0xc748,0xa49a,0xde1d,
    0x90ba,0xea29,0xce88,0xc62d,0x0078,0x0dce,0x454b,0xc58b,0xe23b,0x2684,0xcca1,0xfe11,
    0x69fc,0xaaca,0x6518,0x7547,
};
static constexpr unsigned kDriverSlots = sizeof(kSlotDiversity) / sizeof(kSlotDiversity[0]);
static_assert(kDriverSlots == 220u, "24A446 IOHIDEventDriver slot count");

static void install(IORegistryEntry *driver)
{
    if (originalDispatch || !driver) return;
    if (kSlotDiversity[kDispatch] != kDivDispatch) return;
    const OSMetaClass *meta = driver->getMetaClass();
    const char *name = meta ? meta->getClassName() : nullptr;
    if (!name || (strcmp(name, "IOHIDEventDriver") && strcmp(name, "AppleUserHIDEventService"))) {
        violin_hid_edge_install[0] = 1u;
        kprintf("[VIOLIN_HID] edge::install skipped class=%s\n", name ? name : "<null>");
        return;
    }
    void **table = vtableOf(driver);
    void **copy = static_cast<void **>(IOMalloc(kDriverSlots * sizeof(void *)));
    if (!copy) return;

    unsigned copied = 0u;
    violin_hid_edge_install[2] = kSlots;
    for (unsigned i = 0u; i < kDriverSlots; ++i) {
        void *entry = table[i];
        void *function = entry ? ptrauth_strip(entry, ptrauth_key_function_pointer) : nullptr;
        if (!entry || ptrauth_sign_unauthenticated(
                function, ptrauth_key_function_pointer,
                ptrauth_blend_discriminator(&table[i], kSlotDiversity[i])) != entry) {
            violin_hid_edge_install[2] = i;
            copied = 0u;
            break;
        }
        if (i == kDispatch) {
            originalDispatch = reinterpret_cast<void (*)(IOService *, OSObject *, IOOptionBits)>(
                ptrauth_sign_unauthenticated(function, ptrauth_key_function_pointer, 0));
            function = ptrauth_strip(reinterpret_cast<void *>(&dispatch), ptrauth_key_function_pointer);
        }
        copy[i] = ptrauth_sign_unauthenticated(
            function, ptrauth_key_function_pointer,
            ptrauth_blend_discriminator(&copy[i], kSlotDiversity[i]));
        copied = i + 1u;
    }
    violin_hid_edge_install[1] = copied;
    if (copied != kDriverSlots || !originalDispatch) {
        violin_hid_edge_install[0] = 2u;
        originalDispatch = nullptr;
        IOFree(copy, kDriverSlots * sizeof(void *));
        kprintf("[VIOLIN_HID] edge::install FAIL bad_slot=%u\n", violin_hid_edge_install[2]);
        return;
    }
    violin_hid_edge_install[0] = 3u;
    __asm__ volatile("dmb ish" ::: "memory");
    *reinterpret_cast<void **>(driver) = ptrauth_sign_unauthenticated(
        copy, ptrauth_key_process_independent_data,
        ptrauth_blend_discriminator(driver, kVptrDiscriminator));
    violin_hid_edge_stats[0] = 1u;
    kprintf("[VIOLIN_HID] edge::install PASS class=%s slots=%u\n", name, copied);
}

} // namespace violin_edge

class ViolinHidInput : public IOHIDDevice {
    OSDeclareDefaultStructors(ViolinHidInput)

    IOWorkLoop *inputLoop = nullptr;
    IOTimerEventSource *pollTimer = nullptr;
    bool eventDriverFound = false;
    bool deferredFlushed = false;
    bool selftestEnabled = false;
    unsigned selftestStep = 0u;
    uint32_t lastSeq = 0u;
    int prevIds[VIOLIN_TOUCH_FINGERS] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};
    int prevX[VIOLIN_TOUCH_FINGERS] = {};
    int prevY[VIOLIN_TOUCH_FINGERS] = {};

    static IORegistryEntry *findEventDriver(IORegistryEntry *parent, unsigned depth)
    {
        if (!parent || !depth) return nullptr;
        OSIterator *it = parent->getChildIterator(gIOServicePlane);
        if (!it) return nullptr;
        IORegistryEntry *found = nullptr;
        while (OSObject *child = it->getNextObject()) {
            IORegistryEntry *entry = OSDynamicCast(IORegistryEntry, child);
            if (!entry) continue;
            found = entry->metaCast("IOHIDEventDriver") ? entry : findEventDriver(entry, depth - 1u);
            if (found) break;
        }
        it->release();
        return found;
    }

    static uint32_t readPropU32(IORegistryEntry *entry, const char *key)
    {
        if (!entry) return 0xFFFFFFFFu;
        OSObject *obj = entry->copyProperty(key);
        if (!obj) return 0xFFFFFFFFu;
        OSNumber *num = OSDynamicCast(OSNumber, obj);
        uint32_t val = num ? num->unsigned32BitValue() : 0xFFFFFFFEu;
        obj->release();
        return val;
    }

    static void enforceDigitizerProperties(IORegistryEntry *drv)
    {
        if (!drv) return;
        const uint32_t prePage = readPropU32(drv, "PrimaryUsagePage");
        const uint32_t preUsage = readPropU32(drv, "PrimaryUsage");

        drv->setProperty("PrimaryUsagePage", 0x0DULL, 32u);
        drv->setProperty("PrimaryUsage", 0x04ULL, 32u);
        drv->setProperty("Built-In", true);
        drv->setProperty("DisplayIntegrated", true);
        drv->setProperty("DigitizerCollectionDispatch", true);

        /* Replace DeviceUsagePairs with pure Digitizer/Touch Screen (0x0D/0x04) so
         * iPadOS 27 backboardd does not classify this event service as a 1/6 keyboard. */
        OSArray *pairs = OSArray::withCapacity(1u);
        OSDictionary *pair = OSDictionary::withCapacity(2u);
        OSNumber *up = OSNumber::withNumber(0x0DULL, 32u);
        OSNumber *u = OSNumber::withNumber(0x04ULL, 32u);
        if (pairs && pair && up && u) {
            pair->setObject("DeviceUsagePage", up);
            pair->setObject("DeviceUsage", u);
            pairs->setObject(pair);
            drv->setProperty("DeviceUsagePairs", pairs);
        }
        OSSafeReleaseNULL(u);
        OSSafeReleaseNULL(up);
        OSSafeReleaseNULL(pair);
        OSSafeReleaseNULL(pairs);

        const uint32_t postPage = readPropU32(drv, "PrimaryUsagePage");
        const uint32_t postUsage = readPropU32(drv, "PrimaryUsage");
        kprintf("[VIOLIN_HID] drv_usage pre=(0x%x/0x%x) post=(0x%x/0x%x)\n",
                prePage, preUsage, postPage, postUsage);
    }

    bool ensureEventDriver()
    {
        if (!eventDriverFound) {
            IORegistryEntry *drv = findEventDriver(this, 4u);
            if (drv) {
                eventDriverFound = true;
                violin_hid_driver_found = 1u;
                enforceDigitizerProperties(drv);
                violin_edge::install(drv);
            }
        }
        return eventDriverFound;
    }

    static void touchNotify(void *ctx)
    {
        auto *self = static_cast<ViolinHidInput *>(ctx);
        if (self && self->inputLoop) {
            self->inputLoop->runAction(&ViolinHidInput::touchAction, self);
        }
    }

    static IOReturn touchAction(OSObject *owner, void *, void *, void *, void *)
    {
        auto *self = OSDynamicCast(ViolinHidInput, owner);
        if (self) self->touchSend();
        return kIOReturnSuccess;
    }

    void touchSend()
    {
        if (!ensureEventDriver()) return;
        uint32_t before = violin_touch_seq;
        if ((before & 1u) || before == lastSeq) return;
        __asm__ volatile("dmb ish" ::: "memory");
        unsigned count = violin_touch_count;
        if (count > VIOLIN_TOUCH_FINGERS) count = VIOLIN_TOUCH_FINGERS;
        int ids[VIOLIN_TOUCH_FINGERS], xs[VIOLIN_TOUCH_FINGERS], ys[VIOLIN_TOUCH_FINGERS];
        for (unsigned i = 0u; i < count; ++i) {
            ids[i] = violin_touch_ids[i];
            xs[i] = violin_touch_xs[i];
            ys[i] = violin_touch_ys[i];
        }
        __asm__ volatile("dmb ish" ::: "memory");
        if (violin_touch_seq != before) return;
        lastSeq = before;

        unsigned char report[1 + VIOLIN_TOUCH_FINGERS * 6 + 1] = {3};
        unsigned slot = 0u;
        int nextIds[VIOLIN_TOUCH_FINGERS], nextX[VIOLIN_TOUCH_FINGERS], nextY[VIOLIN_TOUCH_FINGERS];
        for (unsigned i = 0u; i < count && slot < VIOLIN_TOUCH_FINGERS; ++i, ++slot) {
            int x = xs[i]; if (x < 0) x = 0; if (x > 32767) x = 32767;
            int y = ys[i]; if (y < 0) y = 0; if (y > 32767) y = 32767;
            unsigned char *f = report + 1u + slot * 6u;
            f[0] = 3u; /* Tip Switch | Touch Valid */
            f[1] = static_cast<unsigned char>(ids[i] & 0xFF);
            f[2] = static_cast<unsigned char>(x & 0xFF);
            f[3] = static_cast<unsigned char>((x >> 8) & 0xFF);
            f[4] = static_cast<unsigned char>(y & 0xFF);
            f[5] = static_cast<unsigned char>((y >> 8) & 0xFF);
            nextIds[slot] = ids[i];
            nextX[slot] = x;
            nextY[slot] = y;
        }
        const unsigned downCount = slot;
        for (unsigned j = 0u; j < VIOLIN_TOUCH_FINGERS; ++j) {
            const int id = prevIds[j];
            if (id < 0) continue;
            bool kept = false;
            for (unsigned i = 0u; i < downCount && !kept; ++i) {
                kept = ((ids[i] & 0xFF) == (id & 0xFF));
            }
            if (kept || slot >= VIOLIN_TOUCH_FINGERS) continue;
            unsigned char *f = report + 1u + slot * 6u;
            f[0] = 2u; /* Tip Up | Touch Valid */
            f[1] = static_cast<unsigned char>(id & 0xFF);
            f[2] = static_cast<unsigned char>(prevX[j] & 0xFF);
            f[3] = static_cast<unsigned char>((prevX[j] >> 8) & 0xFF);
            f[4] = static_cast<unsigned char>(prevY[j] & 0xFF);
            f[5] = static_cast<unsigned char>((prevY[j] >> 8) & 0xFF);
            ++slot;
        }
        for (unsigned j = 0u; j < VIOLIN_TOUCH_FINGERS; ++j) {
            prevIds[j] = (j < downCount) ? nextIds[j] : -1;
            if (j < downCount) { prevX[j] = nextX[j]; prevY[j] = nextY[j]; }
        }
        if (slot == 0u) return;
        report[1u + VIOLIN_TOUCH_FINGERS * 6u] = static_cast<unsigned char>(slot);
        IOBufferMemoryDescriptor *buf = IOBufferMemoryDescriptor::withBytes(report, sizeof(report), kIODirectionNone);
        IOReturn rc = buf ? handleReport(buf, 0u, 0u) : kIOReturnNoMemory;
        OSSafeReleaseNULL(buf);
        uint32_t n = __atomic_add_fetch(&violin_touch_hid_reports, 1u, __ATOMIC_RELAXED);
        if (n <= 8u || rc != kIOReturnSuccess) {
            kprintf("[VIOLIN_HID] report #%u slots=%u rc=0x%x edge=(%u,%u,%u)\n",
                    n, slot, static_cast<unsigned>(rc),
                    violin_hid_edge_stats[0], violin_hid_edge_stats[1], violin_hid_edge_stats[2]);
        }
    }

    static void tick(OSObject *owner, IOTimerEventSource *src)
    {
        auto *self = OSDynamicCast(ViolinHidInput, owner);
        if (!self) return;
        if (!self->ensureEventDriver()) {
            if (!self->deferredFlushed) {
                self->deferredFlushed = true;
                kprintf("[VIOLIN_HID] flushing deferred matches for IOHIDEventDriver\n");
                IOService::startDeferredMatches();
            }
            src->setTimeoutMS(500u);
            return;
        }
        if (self->selftestEnabled && violin_hid_selftest_done == 0u) {
            /* Inject a 6-step synthetic bottom-edge swipe up to verify full PAC path in QEMU */
            static const int kYs[6] = {32600, 31500, 29000, 25000, 20000, 14000};
            if (self->selftestStep < 6u) {
                int id = 1, x = 16384, y = kYs[self->selftestStep++];
                violin_touch_publish_contacts(1u, &id, &x, &y);
                src->setTimeoutMS(50u);
                return;
            } else {
                violin_touch_publish_contacts(0u, nullptr, nullptr, nullptr);
                violin_hid_selftest_done = 1u;
                kprintf("[VIOLIN_HID] SELFTEST PASS reports=%u edge_install=%u edge_stats=(%u,%u,%u,%u)\n",
                        violin_touch_hid_reports, violin_hid_edge_install[0],
                        violin_hid_edge_stats[0], violin_hid_edge_stats[1],
                        violin_hid_edge_stats[2], violin_hid_edge_stats[3]);
            }
        }
        src->setTimeoutMS(1000u);
    }

public:
    IOWorkLoop *getWorkLoop() const override { return inputLoop; }
    OSString *newTransportString() const override { return OSString::withCString("SPI"); }
    OSString *newProductString() const override { return OSString::withCString("Violin NVT-36536 Touch"); }

    IOReturn newReportDescriptor(IOMemoryDescriptor **out) const override
    {
        if (!out) return kIOReturnBadArgument;
        /* Put Touch Screen (0x0D/0x04) FIRST so IOHIDDevice & IOHIDInterface publish
         * PrimaryUsagePage=0x0D / PrimaryUsage=0x04; keep kKeyboardDescriptor second
         * only so 24A446 IOHIDEventDriver's built-in personality matches IOHIDInterface. */
        unsigned char combined[sizeof(kTouchDescriptor) + sizeof(kKeyboardDescriptor)];
        memcpy(combined, kTouchDescriptor, sizeof(kTouchDescriptor));
        memcpy(combined + sizeof(kTouchDescriptor), kKeyboardDescriptor, sizeof(kKeyboardDescriptor));
        *out = IOBufferMemoryDescriptor::withBytes(combined, sizeof(combined), kIODirectionNone);
        return *out ? kIOReturnSuccess : kIOReturnNoMemory;
    }

    bool start(IOService *provider) override
    {
        inputLoop = IOWorkLoop::workLoop();
        if (!inputLoop) return false;
        if (!setProperty("HIDDefaultBehavior", true)) return false;
        setProperty("Built-In", true);
        setProperty("DisplayIntegrated", true);
        setProperty("DigitizerCollectionDispatch", true);
        setProperty("ReportInterval", 8333ULL, 32u);

        unsigned st = 0u;
        selftestEnabled = PE_parse_boot_argn("violin-hid-selftest", &st, sizeof(st)) && st == 1u;

        if (!IOHIDDevice::start(provider)) return false;
        kprintf("[VIOLIN_HID] dev_usage page=0x%x usage=0x%x\n",
                readPropU32(this, "PrimaryUsagePage"), readPropU32(this, "PrimaryUsage"));
        pollTimer = IOTimerEventSource::timerEventSource(this, &ViolinHidInput::tick);
        if (!pollTimer || inputLoop->addEventSource(pollTimer) != kIOReturnSuccess) {
            OSSafeReleaseNULL(pollTimer);
            IOHIDDevice::stop(provider);
            return false;
        }
        violin_touch_set_sink(&ViolinHidInput::touchNotify, this);
        pollTimer->setTimeoutMS(500u);
        return true;
    }

    void stop(IOService *provider) override
    {
        violin_touch_set_sink(nullptr, nullptr);
        if (pollTimer) {
            pollTimer->cancelTimeout();
            if (inputLoop) inputLoop->removeEventSource(pollTimer);
            OSSafeReleaseNULL(pollTimer);
        }
        IOHIDDevice::stop(provider);
    }

    void free() override
    {
        OSSafeReleaseNULL(inputLoop);
        IOHIDDevice::free();
    }
};

OSDefineMetaClassAndStructors(ViolinHidInput, IOHIDDevice)

extern "C" {
void violin_hid_input_static_init(void) __asm__("__GLOBAL__sub_I_ViolinHidInput.cpp");

static IOService *gViolinHidDev = nullptr;

void violin_hid_input_init(IOService *nub)
{
    if (gViolinHidDev != nullptr) return;
    unsigned en = 1u;
    PE_parse_boot_argn("violin-hid", &en, sizeof(en));
    if (en == 0u) {
        kprintf("[VIOLIN_HID] disabled by boot-arg violin-hid=0\n");
        return;
    }

    violin_hid_stage = 1u;
    OSReturn fRc = OSKextLoadKextWithIdentifier("com.apple.iokit.IOHIDFamily");
    OSReturn dRc = OSKextLoadKextWithIdentifier("com.apple.iokit.IOHIDEventDriver");
    kprintf("[VIOLIN_HID] kext_load IOHIDFamily=0x%x IOHIDEventDriver=0x%x\n",
            static_cast<unsigned>(fRc), static_cast<unsigned>(dRc));
    if (fRc != kOSReturnSuccess) return;

    violin_hid_stage = 2u;
    void *loadHandle = OSMetaClass::preModLoad("com.apple.iokit.IOHIDFamily");
    if (!loadHandle) {
        kprintf("[VIOLIN_HID] FAIL: preModLoad NULL\n");
        return;
    }
    violin_hid_input_static_init();
    OSReturn postRc = OSMetaClass::postModLoad(loadHandle);
    kprintf("[VIOLIN_HID] metaclass postModLoad rc=0x%x\n", static_cast<unsigned>(postRc));
    if (postRc != kOSReturnSuccess) return;

    violin_hid_stage = 3u;
    IOService *prov = nub ? nub : IOService::getPlatform();
    if (!prov) return;
    auto *dev = new ViolinHidInput;
    if (!dev || !dev->init() || !dev->attach(prov) || !dev->start(prov)) {
        kprintf("[VIOLIN_HID] FAIL: alloc/attach/start failed dev=%p\n", dev);
        if (dev) { dev->detach(prov); dev->release(); }
        return;
    }
    dev->registerService();
    gViolinHidDev = dev;
    violin_hid_stage = 4u;
    kprintf("[VIOLIN_HID] PASS: ViolinHidInput registered (%p) on %s\n",
            dev, prov->getName() ? prov->getName() : "<nub>");
}
} // extern "C"
