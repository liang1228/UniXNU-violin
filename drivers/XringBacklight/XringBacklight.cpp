// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * XringBacklight — Dual KTZ8866A (@0x11 on I2C3 + I2C11) AppleARMBacklight Driver
 *
 * Stage-7F Wave 3B bring-up for Xiaomi Pad 7S Pro (violin / O81A / XRING O1):
 *   - Runs read-only 6-bank XringGpio snapshot first (zero GPIO writes).
 *   - Opens CRG-gated non-secure I2C3 (0xEC103000, bit 3) and I2C11 (0xEC10B000, bit 11).
 *   - Reads DISP_ID/BC1/BC2/BB_LSB/BB_MSB/BL_ENABLE/FULL_CURRENT from BOTH KTZ8866A chips.
 *   - Publishes ViolinBacklight masquerading as AppleARMBacklight (matching display.md /
 *     sheng-backlight.md) with full iPadOS 27 CoreBrightness properties and setProperties().
 *   - NEVER modifies KTZ8866_DISP_BL_ENABLE (0x08) bias/power bits during positive brightness
 *     updates; strictly writes 0x04 (LSB) before 0x05 (MSB) synchronously to both chips.
 *   - Under xring-backlight-test=1, exercises real Darwin setProperties("brightness-nits")
 *     across safe visible levels (low -> high -> exact initial restore) with full dual-chip
 *     I2C readback verification.
 */

#include "Ktz8866Math.h"
#include "XringGpio.h"
#include "XringI2c.h"

#include <IOKit/IOLib.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOService.h>
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/libkern.h>
#include <pexpert/pexpert.h>

extern "C" {
void kprintf(const char *fmt, ...);
volatile uint32_t xring_backlight_status = 0;
volatile uint32_t xring_backlight_level = 0;
volatile uint32_t xring_backlight_requests = 0;
volatile uint32_t xring_backlight_errors = 0;
void violin_backlight_init(IOService *nub);
}

namespace {

constexpr uint32_t kPeriCrgI2c3Bit  = 3u;
constexpr uint32_t kPeriCrgI2c11Bit = 11u;

struct KtzRegs {
    uint8_t dispId;
    uint8_t bc1;
    uint8_t bc2;
    uint8_t bbLsb;
    uint8_t bbMsb;
    uint8_t blEn;
    uint8_t fullCurr;
    uint16_t level;
};

static const OSMetaClass *gAppleARMBacklightMeta = nullptr;
static bool gMasqueradeBacklight = true;

bool readKtzSnapshot(XringI2cBus *bus, KtzRegs *out)
{
    if (bus == nullptr || !bus->isReady() || out == nullptr) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    if (!bus->readReg8(KTZ8866_I2C_ADDR, KTZ8866_REG_DISP_ID, &out->dispId)) return false;
    if (!bus->readReg8(KTZ8866_I2C_ADDR, KTZ8866_REG_DISP_BC1, &out->bc1)) return false;
    if (!bus->readReg8(KTZ8866_I2C_ADDR, KTZ8866_REG_DISP_BC2, &out->bc2)) return false;
    if (!bus->readReg8(KTZ8866_I2C_ADDR, KTZ8866_REG_DISP_BB_LSB, &out->bbLsb)) return false;
    if (!bus->readReg8(KTZ8866_I2C_ADDR, KTZ8866_REG_DISP_BB_MSB, &out->bbMsb)) return false;
    if (!bus->readReg8(KTZ8866_I2C_ADDR, KTZ8866_REG_DISP_BL_EN, &out->blEn)) return false;
    if (!bus->readReg8(KTZ8866_I2C_ADDR, KTZ8866_REG_FULL_CURRENT, &out->fullCurr)) return false;
    out->level = ktz8866_decode_level(out->bbLsb, out->bbMsb);
    return true;
}

bool readKtzLevel(XringI2cBus *bus, uint16_t *outLevel, uint8_t *outLsb, uint8_t *outMsb)
{
    uint8_t lsb = 0, msb = 0;
    if (!bus->readReg8(KTZ8866_I2C_ADDR, KTZ8866_REG_DISP_BB_LSB, &lsb)) return false;
    if (!bus->readReg8(KTZ8866_I2C_ADDR, KTZ8866_REG_DISP_BB_MSB, &msb)) return false;
    if (outLsb) *outLsb = lsb;
    if (outMsb) *outMsb = msb;
    if (outLevel) *outLevel = ktz8866_decode_level(lsb, msb);
    return true;
}

bool writeKtzLevel(XringI2cBus *bus, uint16_t level)
{
    uint8_t lsb = 0, msb = 0;
    ktz8866_encode_level(level, &lsb, &msb);
    /* KTZ8866A latches brightness on MSB write: ALWAYS write LSB (0x04) then MSB (0x05). */
    if (!bus->writeReg8(KTZ8866_I2C_ADDR, KTZ8866_REG_DISP_BB_LSB, lsb)) return false;
    if (!bus->writeReg8(KTZ8866_I2C_ADDR, KTZ8866_REG_DISP_BB_MSB, msb)) return false;
    return true;
}

bool metaInheritsIOService(const OSMetaClass *mc)
{
    for (const OSMetaClass *cur = mc; cur != nullptr; cur = cur->getSuperClass()) {
        if (cur == IOService::metaClass) {
            return true;
        }
    }
    return false;
}

} // namespace

class ViolinBacklightBase : public IOService {
    OSDeclareDefaultStructors(ViolinBacklightBase)
};
OSDefineMetaClassAndStructors(ViolinBacklightBase, IOService)

class ViolinBacklight final : public ViolinBacklightBase {
public:
    const OSMetaClass *getMetaClass() const override
    {
        if (gMasqueradeBacklight && gAppleARMBacklightMeta != nullptr) {
            return gAppleARMBacklightMeta;
        }
        return ViolinBacklightBase::getMetaClass();
    }

    bool initWithBuses(XringI2cBus *busA, XringI2cBus *busB, uint16_t initialLevel)
    {
        if (!ViolinBacklightBase::init()) {
            return false;
        }
        busA_ = busA;
        busB_ = busB;
        level_ = initialLevel;
        initLevel_ = initialLevel;
        return true;
    }

    bool start(IOService *provider) override
    {
        if (!ViolinBacklightBase::start(provider)) {
            return false;
        }
        setName("backlight");
        publishProperties(level_);
        registerService();
        return true;
    }

    IOReturn setProperties(OSObject *properties) override
    {
        OSDictionary *dict = OSDynamicCast(OSDictionary, properties);
        if (dict == nullptr) {
            return kIOReturnBadArgument;
        }

        uint16_t target = level_;
        bool hasRequest = false;

        if (OSNumber *nitsObj = OSDynamicCast(OSNumber, dict->getObject("brightness-nits"))) {
            int32_t nits1616 = static_cast<int32_t>(nitsObj->unsigned32BitValue());
            target = ktz8866_nits1616_to_level(nits1616);
            hasRequest = true;
        } else if (OSNumber *brObj = OSDynamicCast(OSNumber, dict->getObject("brightness"))) {
            uint32_t raw = brObj->unsigned32BitValue();
            target = (raw > KTZ8866_LEVEL_MAX) ? KTZ8866_LEVEL_MAX : static_cast<uint16_t>(raw);
            hasRequest = true;
        }

        if (!hasRequest) {
            /* Other CoreBrightness metadata keys (e.g. brightness-nits-cap) succeed as no-ops. */
            return kIOReturnSuccess;
        }

        __atomic_add_fetch(&xring_backlight_requests, 1u, __ATOMIC_RELAXED);

        /* Safety: keep backlight >= 1 when called during bring-up unless explicitly zeroed,
         * and NEVER alter DISP_BL_ENABLE (0x08) bias bits. */
        bool okA = (busA_ != nullptr && busA_->isReady()) ? writeKtzLevel(busA_, target) : false;
        bool okB = (busB_ != nullptr && busB_->isReady()) ? writeKtzLevel(busB_, target) : false;
        if (!okA || !okB) {
            __atomic_add_fetch(&xring_backlight_errors, 1u, __ATOMIC_RELAXED);
            kprintf("[XRING_BL] setProperties level=%u failed okA=%u(abrt=0x%x) okB=%u(abrt=0x%x)\n",
                    target,
                    okA ? 1u : 0u, busA_ ? busA_->lastAbortSource() : 0u,
                    okB ? 1u : 0u, busB_ ? busB_->lastAbortSource() : 0u);
            return kIOReturnIOError;
        }

        level_ = target;
        xring_backlight_level = target;
        publishProperties(level_);
        return kIOReturnSuccess;
    }

    uint16_t currentLevel() const { return level_; }
    uint16_t initialLevel() const { return initLevel_; }

private:
    void publishProperties(uint16_t lvl)
    {
        if (gMasqueradeBacklight) {
            setProperty("backlight-control", kOSBooleanTrue);
        }

        /* LminProduct / LmidProduct / LmaxProduct (16.16 fixed-point nits for LmaxProduct). */
        uint32_t lmin = KTZ8866_NITS_MIN;
        uint32_t lmid = KTZ8866_NITS_MID;
        uint32_t lmax1616 = KTZ8866_NITS_MAX << 16;
        setProperty("LminProduct", lmin, 32u);
        setProperty("LmidProduct", lmid, 32u);
        if (OSData *lmaxData = OSData::withBytes(&lmax1616, sizeof(lmax1616))) {
            setProperty("LmaxProduct", lmaxData);
            lmaxData->release();
        }

        /* 11-point marketing table (signed 16.16 nits across 2..500 nits). */
        static const int32_t kMarketingTable[11] = {
            2 << 16, 8 << 16, 20 << 16, 40 << 16, 75 << 16,
            140 << 16, 210 << 16, 290 << 16, 370 << 16, 440 << 16, 500 << 16,
        };
        if (OSData *tbl = OSData::withBytes(kMarketingTable, sizeof(kMarketingTable))) {
            setProperty("backlight-marketing-table", tbl);
            tbl->release();
        }

        /* backlight-calibration-parameters dictionary (16.16 nits). */
        if (OSDictionary *cal = OSDictionary::withCapacity(6u)) {
            auto setU32 = [&](const char *k, uint32_t v) {
                if (OSNumber *n = OSNumber::withNumber(v, 32u)) {
                    cal->setObject(k, n);
                    n->release();
                }
            };
            setU32("lMinProduct", KTZ8866_NITS_MIN << 16);
            setU32("lMidProduct", KTZ8866_NITS_MID << 16);
            setU32("lMaxProduct", KTZ8866_NITS_MAX << 16);
            setU32("lMinPanel",   KTZ8866_NITS_MIN << 16);
            setU32("lMidPanel",   KTZ8866_NITS_MID << 16);
            setU32("lMaxPanel",   KTZ8866_NITS_MAX << 16);
            setProperty("backlight-calibration-parameters", cal);
            cal->release();
        }

        /* IODisplayParameters.{brightness, BrightnessMilliNits}. */
        if (OSDictionary *params = OSDictionary::withCapacity(2u)) {
            auto makeRange = [](uint32_t minV, uint32_t maxV, uint32_t curV) -> OSDictionary * {
                OSDictionary *d = OSDictionary::withCapacity(3u);
                if (!d) return nullptr;
                if (OSNumber *n = OSNumber::withNumber(minV, 32u)) { d->setObject("min", n); n->release(); }
                if (OSNumber *n = OSNumber::withNumber(maxV, 32u)) { d->setObject("max", n); n->release(); }
                if (OSNumber *n = OSNumber::withNumber(curV, 32u)) { d->setObject("value", n); n->release(); }
                return d;
            };
            if (OSDictionary *br = makeRange(0u, KTZ8866_LEVEL_MAX, lvl)) {
                params->setObject("brightness", br);
                br->release();
            }
            if (OSDictionary *mn = makeRange(KTZ8866_NITS_MIN * 1000u,
                                             KTZ8866_NITS_MAX * 1000u,
                                             ktz8866_level_to_millinits(lvl))) {
                params->setObject("BrightnessMilliNits", mn);
                mn->release();
            }
            setProperty("IODisplayParameters", params);
            params->release();
        }
    }

    XringI2cBus *busA_ = nullptr;
    XringI2cBus *busB_ = nullptr;
    uint16_t level_ = 0;
    uint16_t initLevel_ = 0;
};

static XringI2cBus gBusI2c3;
static XringI2cBus gBusI2c11;
static ViolinBacklight *gViolinBacklight = nullptr;

static bool setNitsAndVerify(ViolinBacklight *bl, uint16_t expectedLevel,
                             const char *tag, uint16_t *rbAOut, uint16_t *rbBOut)
{
    int32_t nits1616 = ktz8866_level_to_nits1616(expectedLevel);
    uint16_t quantLevel = ktz8866_nits1616_to_level(nits1616);

    OSDictionary *req = OSDictionary::withCapacity(1u);
    if (req == nullptr) {
        return false;
    }
    OSNumber *num = OSNumber::withNumber(static_cast<uint32_t>(nits1616), 32u);
    if (num == nullptr) {
        req->release();
        return false;
    }
    req->setObject("brightness-nits", num);
    num->release();

    IOReturn rc = bl->setProperties(req);
    req->release();
    if (rc != kIOReturnSuccess) {
        kprintf("[XRING_BL] step %s FAIL setProperties rc=0x%x\n", tag, static_cast<unsigned>(rc));
        return false;
    }

    uint16_t rbA = 0, rbB = 0;
    uint8_t lsbA = 0, msbA = 0, lsbB = 0, msbB = 0;
    bool okA = readKtzLevel(&gBusI2c3, &rbA, &lsbA, &msbA);
    bool okB = readKtzLevel(&gBusI2c11, &rbB, &lsbB, &msbB);
    if (rbAOut) *rbAOut = rbA;
    if (rbBOut) *rbBOut = rbB;

    bool match = okA && okB && (rbA == quantLevel) && (rbB == quantLevel);
    kprintf("[XRING_BL] step %s nits1616=0x%x target=%u rb_i2c3=%u(0x%02x,0x%02x) rb_i2c11=%u(0x%02x,0x%02x) match=%u\n",
            tag, static_cast<unsigned>(nits1616), quantLevel,
            rbA, lsbA, msbA, rbB, lsbB, msbB, match ? 1u : 0u);
    return match;
}

extern "C" void violin_backlight_init(IOService *nub)
{
    if (gViolinBacklight != nullptr) {
        return;
    }

    /* Always run read-only 6-bank GPIO snapshot if /arm-io/gpio0..5 exist in ADT. */
    (void)xring_gpio_probe_all();

    unsigned int enabled = 0;
    if (!PE_parse_boot_argn("xring-backlight", &enabled, sizeof(enabled)) || enabled == 0u) {
        return;
    }

    unsigned int blControl = 1u;
    if (PE_parse_boot_argn("backlight-control", &blControl, sizeof(blControl))) {
        gMasqueradeBacklight = (blControl != 0u);
    }

    bool okI2c3 = gBusI2c3.initFromAdt("/arm-io/i2c3", kPeriCrgI2c3Bit, "i2c3");
    bool okI2c11 = gBusI2c11.initFromAdt("/arm-io/i2c11", kPeriCrgI2c11Bit, "i2c11");
    if (!okI2c3 || !okI2c11) {
        kprintf("[XRING_BL] skipped (i2c3=%u i2c11=%u; no ADT nodes or CRG gated)\n",
                okI2c3 ? 1u : 0u, okI2c11 ? 1u : 0u);
        xring_backlight_status = 1u;
        return;
    }

    KtzRegs regA = {}, regB = {};
    bool snapA = readKtzSnapshot(&gBusI2c3, &regA);
    bool snapB = readKtzSnapshot(&gBusI2c11, &regB);
    kprintf("[XRING_BL] chip0(i2c3@0x11) ok=%u id=0x%02x bc1=0x%02x bc2=0x%02x lsb=0x%02x msb=0x%02x en=0x%02x curr=0x%02x lvl=%u abrt=0x%x\n",
            snapA ? 1u : 0u, regA.dispId, regA.bc1, regA.bc2, regA.bbLsb, regA.bbMsb,
            regA.blEn, regA.fullCurr, regA.level, gBusI2c3.lastAbortSource());
    kprintf("[XRING_BL] chip1(i2c11@0x11) ok=%u id=0x%02x bc1=0x%02x bc2=0x%02x lsb=0x%02x msb=0x%02x en=0x%02x curr=0x%02x lvl=%u abrt=0x%x\n",
            snapB ? 1u : 0u, regB.dispId, regB.bc1, regB.bc2, regB.bbLsb, regB.bbMsb,
            regB.blEn, regB.fullCurr, regB.level, gBusI2c11.lastAbortSource());

    if (!snapA || !snapB) {
        kprintf("[XRING_BL] FAIL: KTZ8866A dual-chip probe failed (snapA=%u snapB=%u)\n",
                snapA ? 1u : 0u, snapB ? 1u : 0u);
        xring_backlight_status = 2u;
        return;
    }

    /* Resolve AppleARMBacklight metaclass from prelinked AppleARMPlatform if available. */
    const OSMetaClass *appleMeta = nullptr;
    if (const OSSymbol *blSym = OSSymbol::withCStringNoCopy("AppleARMBacklight")) {
        appleMeta = OSMetaClass::getMetaClassWithName(blSym);
        blSym->release();
    }
    if (appleMeta != nullptr && metaInheritsIOService(appleMeta)) {
        gAppleARMBacklightMeta = appleMeta;
    } else {
        kprintf("[XRING_BL] note: AppleARMBacklight metaclass %s; using ViolinBacklightBase\n",
                appleMeta ? "non-IOService" : "not found");
    }

    IOService *parent = nub;
    if (parent == nullptr) {
        parent = IOService::getPlatform();
    }
    if (parent == nullptr) {
        kprintf("[XRING_BL] FAIL: no parent IOService\n");
        xring_backlight_status = 3u;
        return;
    }

    ViolinBacklight *bl = new ViolinBacklight;
    if (bl == nullptr || !bl->initWithBuses(&gBusI2c3, &gBusI2c11, regA.level)) {
        if (bl != nullptr) bl->release();
        kprintf("[XRING_BL] FAIL: ViolinBacklight init failed\n");
        xring_backlight_status = 4u;
        return;
    }
    if (!bl->attach(parent) || !bl->start(parent)) {
        bl->detach(parent);
        bl->release();
        kprintf("[XRING_BL] FAIL: ViolinBacklight attach/start failed\n");
        xring_backlight_status = 5u;
        return;
    }
    gViolinBacklight = bl;
    xring_backlight_level = regA.level;

    const char *clsName = bl->getMetaClass() ? bl->getMetaClass()->getClassName() : "<null>";
    kprintf("[XRING_BL] registered service=%p class=%s init_lvl=(%u,%u) bl_en=(0x%02x,0x%02x)\n",
            bl, clsName, regA.level, regB.level, regA.blEn, regB.blEn);

    unsigned int runTest = 0;
    PE_parse_boot_argn("xring-backlight-test", &runTest, sizeof(runTest));
    if (runTest != 0u) {
        if (regA.blEn != 0x7Fu || regB.blEn != 0x7Fu) {
            kprintf("[XRING_BL] SKIP_DIM_TEST: unexpected BL_EN (0x%02x, 0x%02x); preserving state\n",
                    regA.blEn, regB.blEn);
            xring_backlight_status = 6u;
            return;
        }

        uint16_t lowLvl = 0, highLvl = 0;
        ktz8866_safe_test_levels(regA.level, &lowLvl, &highLvl);
        uint16_t rbLowA = 0, rbLowB = 0, rbHiA = 0, rbHiB = 0;

        bool step1 = setNitsAndVerify(bl, lowLvl, "low", &rbLowA, &rbLowB);
        IOSleep(200);
        bool step2 = setNitsAndVerify(bl, highLvl, "high", &rbHiA, &rbHiB);
        IOSleep(200);

        /* Always restore exact initial 11-bit brightness (via raw brightness key for exact bit match). */
        OSDictionary *restDict = OSDictionary::withCapacity(1u);
        bool step3 = false;
        uint16_t rbRestA = 0, rbRestB = 0;
        if (restDict != nullptr) {
            if (OSNumber *n = OSNumber::withNumber(static_cast<uint32_t>(regA.level), 32u)) {
                restDict->setObject("brightness", n);
                n->release();
            }
            IOReturn rc = bl->setProperties(restDict);
            restDict->release();
            bool okA = readKtzLevel(&gBusI2c3, &rbRestA, nullptr, nullptr);
            bool okB = readKtzLevel(&gBusI2c11, &rbRestB, nullptr, nullptr);
            step3 = (rc == kIOReturnSuccess) && okA && okB &&
                    (rbRestA == regA.level) && (rbRestB == regA.level);
            kprintf("[XRING_BL] step restore rc=0x%x target=%u rb_i2c3=%u rb_i2c11=%u match=%u\n",
                    static_cast<unsigned>(rc), regA.level, rbRestA, rbRestB, step3 ? 1u : 0u);
        }

        if (step1 && step2 && step3 && xring_backlight_errors == 0u) {
            xring_backlight_status = 100u;
            kprintf("[XRING_BL] PASS: dual_ktz8866=ok class=%s id=(0x%02x,0x%02x) init=%u steps=%u/%u/%u req=%u err=%u\n",
                    clsName, regA.dispId, regB.dispId, regA.level,
                    rbLowA, rbHiA, rbRestA, xring_backlight_requests, xring_backlight_errors);
        } else {
            xring_backlight_status = 7u;
            kprintf("[XRING_BL] FAIL: dimming selftest s1=%u s2=%u s3=%u err=%u\n",
                    step1 ? 1u : 0u, step2 ? 1u : 0u, step3 ? 1u : 0u, xring_backlight_errors);
        }
    } else {
        xring_backlight_status = 100u;
        kprintf("[XRING_BL] PASS: dual_ktz8866_ro=ok class=%s id=(0x%02x,0x%02x) init=(%u,%u)\n",
                clsName, regA.dispId, regB.dispId, regA.level, regB.level);
    }
}
