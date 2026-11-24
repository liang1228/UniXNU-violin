// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * ViolinStorageProbe — Stage-7G Wave 3A board coordinator:
 *   1. Starts & self-tests AppleKeyStoreState (aks=1, aks-sls=3) in QEMU & live.
 *   2. When /arm-io/ufshc is present and xring-ufs-blk=1 is set:
 *      - Loads closed-source com.apple.iokit.IOStorageFamily.
 *      - Late-registers UniXNUBlockStorageDevice (parent = closed-source
 *        IOBlockStorageDevice) + strictly read-only XringUfsBlock inside
 *        OSMetaClass::preModLoad("com.apple.iokit.IOStorageFamily")..postModLoad().
 *      - Attaches XringUfsBlock to /arm-io/ufshc, verifying that Apple's closed-source
 *        IOBlockStorageDriver + IOGUIDPartitionScheme + IOMediaBSDClient publish
 *        whole-disk IOMedia (Writable=0) and real LUN 2 child IOMedia partitions
 *        (userdata, boot_a, boot_b).
 *      - Verifies direct kIODirectionOut write rejection (kIOReturnNotWritable),
 *        IOMedia RW-open refusal, and end-to-end boot_a ANDROID! v4 header read
 *        directly through Apple's closed-source IOMedia -> IOBlockStorageDriver ->
 *        XringUfsBlock -> live XRING O1 UFSHCI 4.0.
 */

#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOService.h>
#include <IOKit/storage/IOMedia.h>
#include <kern/clock.h>
#include <kern/task.h>
#include <libkern/OSKextLib.h>
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSIterator.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/libkern.h>
#include <pexpert/pexpert.h>

#include "XringUfsBlock.h"

extern "C" {
void kprintf(const char *fmt, ...);

/* From KeyStoreGlue.cpp */
bool violin_keystore_init_and_selftest(void);

/* Globalized deferred static constructors (__mod_init_func removed by build-violin-source-storage.py). */
void violin_ioblockstoragedevice_static_init(void) __asm__("__GLOBAL__sub_I_IOBlockStorageDevice.cpp");
void violin_xringufsblock_static_init(void) __asm__("__GLOBAL__sub_I_XringUfsBlock.cpp");

static const OSMetaClass *gParentBlockStorageMetaClass = nullptr;

const OSMetaClass *native_source_storage_parent(void)
{
    return gParentBlockStorageMetaClass;
}

void violin_storage_init(IOService *nub);
} // extern "C"

namespace {

IOService *gViolinUfsBlock = nullptr;

/* Expected LUN 2 (/dev/block/sdc) partition ground truth (4096 B blocks). */
constexpr uint64_t kBlkSize              = 4096ULL;
constexpr uint64_t kExpectedWholeSize    = 129089536ULL * kBlkSize; /* 528,750,739,456 B */
constexpr uint64_t kExpectedUserBase     = 3138056ULL * kBlkSize;
constexpr uint64_t kExpectedUserSize     = (129089527ULL - 3138056ULL + 1ULL) * kBlkSize;
constexpr uint64_t kExpectedBootABase    = 52104ULL * kBlkSize;
constexpr uint64_t kExpectedBootASize    = (76679ULL - 52104ULL + 1ULL) * kBlkSize;
constexpr uint64_t kExpectedBootBBase    = 197256ULL * kBlkSize;
constexpr uint64_t kExpectedBootBSize    = (221831ULL - 197256ULL + 1ULL) * kBlkSize;

inline uint32_t readLe32(const uint8_t *p)
{
    uint32_t v = 0;
    memcpy(&v, p, sizeof(v));
    return v;
}

bool getNumProp(IOService *svc, const char *key, uint64_t *out)
{
    OSNumber *n = OSDynamicCast(OSNumber, svc->getProperty(key));
    if (!n) return false;
    *out = n->unsigned64BitValue();
    return true;
}

bool getBoolProp(IOService *svc, const char *key, bool *out)
{
    OSBoolean *b = OSDynamicCast(OSBoolean, svc->getProperty(key));
    if (!b) return false;
    *out = b->getValue();
    return true;
}

void getStrProp(IOService *svc, const char *key, char *dst, size_t cap)
{
    dst[0] = '\0';
    OSString *s = OSDynamicCast(OSString, svc->getProperty(key));
    if (s && s->getCStringNoCopy()) {
        strlcpy(dst, s->getCStringNoCopy(), cap);
    }
}

bool isDescendantOf(IOService *svc, IOService *ancestor)
{
    unsigned depth = 0;
    for (IOService *p = svc; p && depth++ < 32u; p = p->getProvider()) {
        if (p == ancestor) {
            return true;
        }
    }
    return false;
}

} // namespace

extern "C" void violin_storage_init(IOService *nub)
{
    /* Phase A: AppleKeyStoreState (runs in both QEMU and live violin when aks=1). */
    (void)violin_keystore_init_and_selftest();

    /* Phase B: Strictly Read-Only XringUfsBlock -> IOStorageFamily -> IOMedia (live violin). */
    if (gViolinUfsBlock != nullptr) {
        return;
    }

    uint32_t blkEnabled = 0u;
    if (!PE_parse_boot_argn("xring-ufs-blk", &blkEnabled, sizeof(blkEnabled)) || blkEnabled != 1u) {
        return;
    }

    IORegistryEntry *ufshcEntry = IORegistryEntry::fromPath("/arm-io/ufshc", gIODTPlane);
    if (!ufshcEntry) {
        kprintf("[XRING_UFS_BLK] skipped (no /arm-io/ufshc in ADT)\n");
        return;
    }
    IOService *provider = OSDynamicCast(IOService, ufshcEntry);
    if (!provider) {
        ufshcEntry->release();
        provider = nub ? nub->getProvider() : IOService::getPlatform();
        if (provider) {
            provider->retain();
        }
    }
    if (!provider) {
        kprintf("[XRING_UFS_BLK] FAIL: no valid provider for XringUfsBlock\n");
        return;
    }

    /* 1. Ensure closed-source com.apple.iokit.IOStorageFamily is loaded. */
    OSReturn kextRc = OSKextLoadKextWithIdentifier("com.apple.iokit.IOStorageFamily");
    const OSSymbol *baseSym = OSSymbol::withCStringNoCopy("IOBlockStorageDevice");
    const OSMetaClass *parentMc = baseSym ? OSMetaClass::getMetaClassWithName(baseSym) : nullptr;
    if (baseSym) {
        baseSym->release();
    }
    kprintf("[XRING_UFS_BLK] IOStorageFamily load=0x%x parent_mc=%p(%s,sz=%u)\n",
            static_cast<unsigned>(kextRc),
            parentMc,
            parentMc ? parentMc->getClassName() : "<null>",
            parentMc ? parentMc->getClassSize() : 0u);
    if (kextRc != kOSReturnSuccess || !parentMc) {
        provider->release();
        kprintf("[XRING_UFS_BLK] FAIL: IOStorageFamily or IOBlockStorageDevice metaclass unavailable\n");
        return;
    }

    /* 2. Late-register UniXNUBlockStorageDevice -> XringUfsBlock below closed-source IOBlockStorageDevice. */
    gParentBlockStorageMetaClass = parentMc;
    void *loadHandle = OSMetaClass::preModLoad("com.apple.iokit.IOStorageFamily");
    if (!loadHandle) {
        provider->release();
        kprintf("[XRING_UFS_BLK] FAIL: OSMetaClass::preModLoad returned NULL\n");
        return;
    }
    violin_ioblockstoragedevice_static_init();
    violin_xringufsblock_static_init();
    OSReturn postRc = OSMetaClass::postModLoad(loadHandle);
    kprintf("[XRING_UFS_BLK] late metaclass postModLoad rc=0x%x\n", static_cast<unsigned>(postRc));
    if (postRc != kOSReturnSuccess) {
        provider->release();
        kprintf("[XRING_UFS_BLK] FAIL: OSMetaClass::postModLoad failed\n");
        return;
    }

    /* 3. Instantiate, attach, and start XringUfsBlock (triggers IOBlockStorageDriver + IOGUIDPartitionScheme). */
    IOService *ufsDev = xring_ufs_block_allocate();
    if (!ufsDev || !ufsDev->init()) {
        if (ufsDev) ufsDev->release();
        provider->release();
        kprintf("[XRING_UFS_BLK] FAIL: XringUfsBlock allocate/init failed\n");
        return;
    }
    const OSMetaClass *devMc = ufsDev->getMetaClass();
    const OSMetaClass *midMc = devMc ? devMc->getSuperClass() : nullptr;
    const OSMetaClass *topMc = midMc ? midMc->getSuperClass() : nullptr;
    kprintf("[XRING_UFS_BLK] chain=%s -> %s -> %s (size=%u)\n",
            devMc ? devMc->getClassName() : "?",
            midMc ? midMc->getClassName() : "?",
            topMc ? topMc->getClassName() : "?",
            devMc ? devMc->getClassSize() : 0u);

    if (!ufsDev->attach(provider) || !ufsDev->start(provider)) {
        ufsDev->detach(provider);
        ufsDev->release();
        provider->release();
        kprintf("[XRING_UFS_BLK] FAIL: XringUfsBlock attach/start failed\n");
        return;
    }
    provider->release();
    gViolinUfsBlock = ufsDev;

    /* 4. Negative check #1: direct write request to XringUfsBlock MUST fail with kIOReturnNotWritable. */
    int writeRejRc = xring_ufs_block_test_write_reject(ufsDev);
    bool directWriteRejected = (static_cast<IOReturn>(writeRejRc) == kIOReturnNotWritable);

    /* 5. Wait up to 3.0 s for Apple IOBlockStorageDriver + IOGUIDPartitionScheme + IOMediaBSDClient. */
    bool wholeFound = false, wholeWritable = true;
    uint64_t wholeSize = 0, wholeBlk = 0;
    char wholeBsd[32] = {};

    bool userFound = false, userWritable = true;
    uint64_t userBase = 0, userSize = 0;
    char userBsd[32] = {};

    bool bootAFound = false, bootAWritable = true;
    uint64_t bootABase = 0, bootASize = 0;
    char bootABsd[32] = {};
    IOService *bootAMedia = nullptr;

    bool bootBFound = false, bootBWritable = true;
    uint64_t bootBBase = 0, bootBSize = 0;
    char bootBBsd[32] = {};

    uint32_t childPartitions = 0;

    uint64_t deadline = 0;
    clock_interval_to_deadline(3000u, kMillisecondScale, &deadline);
    while (true) {
        wholeFound = userFound = bootAFound = bootBFound = false;
        childPartitions = 0;
        if (bootAMedia) {
            bootAMedia->release();
            bootAMedia = nullptr;
        }

        OSDictionary *match = IOService::serviceMatching("IOMedia");
        OSIterator *it = match ? IOService::getMatchingServices(match) : nullptr;
        if (match) match->release();
        if (it) {
            while (OSObject *obj = it->getNextObject()) {
                IOService *media = OSDynamicCast(IOService, obj);
                if (!media || !isDescendantOf(media, ufsDev)) {
                    continue;
                }
                bool whole = false, writable = true;
                uint64_t sz = 0, base = 0, blk = 0;
                (void)getBoolProp(media, "Whole", &whole);
                (void)getBoolProp(media, "Writable", &writable);
                (void)getNumProp(media, "Size", &sz);
                (void)getNumProp(media, "Base", &base);
                (void)getNumProp(media, "Preferred Block Size", &blk);
                const char *mname = media->getName();

                if (whole) {
                    wholeFound = true;
                    wholeWritable = writable;
                    wholeSize = sz;
                    wholeBlk = blk;
                    getStrProp(media, kIOBSDNameKey, wholeBsd, sizeof(wholeBsd));
                } else {
                    childPartitions++;
                    if (mname && strcmp(mname, "userdata") == 0) {
                        userFound = true;
                        userWritable = writable;
                        userBase = base;
                        userSize = sz;
                        getStrProp(media, kIOBSDNameKey, userBsd, sizeof(userBsd));
                    } else if (mname && strcmp(mname, "boot_a") == 0) {
                        bootAFound = true;
                        bootAWritable = writable;
                        bootABase = base;
                        bootASize = sz;
                        getStrProp(media, kIOBSDNameKey, bootABsd, sizeof(bootABsd));
                        media->retain();
                        bootAMedia = media;
                    } else if (mname && strcmp(mname, "boot_b") == 0) {
                        bootBFound = true;
                        bootBWritable = writable;
                        bootBBase = base;
                        bootBSize = sz;
                        getStrProp(media, kIOBSDNameKey, bootBBsd, sizeof(bootBBsd));
                    }
                }
            }
            it->release();
        }

        if (wholeFound && userFound && bootAFound && bootBFound && childPartitions >= 80u &&
            wholeBsd[0] != '\0' && userBsd[0] != '\0' && bootABsd[0] != '\0') {
            break;
        }
        if (mach_absolute_time() >= deadline) {
            break;
        }
        IOSleep(50u);
    }

    kprintf("[XRING_UFS_BLK] iomedia whole=%u(bsd=%s,sz=%llu,blk=%llu,wr=%u) parts=%u userdata=%u(bsd=%s,base=%llu,sz=%llu,wr=%u) boot_a=%u(bsd=%s,base=%llu,sz=%llu,wr=%u) boot_b=%u(bsd=%s)\n",
            wholeFound ? 1u : 0u, wholeBsd[0] ? wholeBsd : "-",
            static_cast<unsigned long long>(wholeSize), static_cast<unsigned long long>(wholeBlk),
            wholeWritable ? 1u : 0u, childPartitions,
            userFound ? 1u : 0u, userBsd[0] ? userBsd : "-",
            static_cast<unsigned long long>(userBase), static_cast<unsigned long long>(userSize),
            userWritable ? 1u : 0u,
            bootAFound ? 1u : 0u, bootABsd[0] ? bootABsd : "-",
            static_cast<unsigned long long>(bootABase), static_cast<unsigned long long>(bootASize),
            bootAWritable ? 1u : 0u,
            bootBFound ? 1u : 0u, bootBBsd[0] ? bootBBsd : "-");

    /* 6. End-to-end read-through-IOMedia + negative RW-open test on boot_a child IOMedia. */
    bool rwOpenRefused = false;
    bool mediaReadOk = false;
    uint32_t bootHdrVer = 0, bootKernelSz = 0;

    if (bootAMedia && bootAMedia->metaCast("IOMedia") != nullptr) {
        IOService *client = nub ? nub : static_cast<IOService *>(IOService::getPlatform());
        auto *storage = static_cast<IOStorage *>(bootAMedia);

        /* Negative check #2: opening read-only IOMedia for read-write MUST fail. */
        bool rwOpened = storage->open(client, 0u, kIOStorageAccessReaderWriter);
        if (rwOpened) {
            storage->close(client, 0u);
            rwOpenRefused = false;
        } else {
            rwOpenRefused = true;
        }

        /* Positive check: read 4096 B at offset 0 of boot_a IOMedia -> ANDROID! v4 header. */
        if (storage->open(client, 0u, kIOStorageAccessReader)) {
            auto *readDesc = IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task, kIODirectionIn, 4096u, 4096u);
            if (readDesc) {
                IOReturn rrc = storage->read(client, 0ULL, readDesc);
                if (rrc == kIOReturnSuccess) {
                    const uint8_t *p = static_cast<const uint8_t *>(readDesc->getBytesNoCopy());
                    if (p && memcmp(p, "ANDROID!", 8u) == 0) {
                        bootKernelSz = readLe32(p + 8);
                        bootHdrVer = readLe32(p + 40);
                        mediaReadOk = (bootHdrVer == 4u && bootKernelSz > 0u);
                    }
                }
                kprintf("[XRING_UFS_BLK] boot_a iomedia read rc=0x%x magic_ok=%u hdr_ver=%u kernel_sz=%u rw_open_refused=%u\n",
                        static_cast<unsigned>(rrc), mediaReadOk ? 1u : 0u, bootHdrVer, bootKernelSz,
                        rwOpenRefused ? 1u : 0u);
                readDesc->release();
            }
            storage->close(client, 0u);
        }
    }
    if (bootAMedia) {
        bootAMedia->release();
        bootAMedia = nullptr;
    }

    bool allOk = directWriteRejected &&
                 wholeFound && !wholeWritable && wholeSize == kExpectedWholeSize && wholeBlk == kBlkSize &&
                 childPartitions == 80u &&
                 userFound && !userWritable && userBase == kExpectedUserBase && userSize == kExpectedUserSize &&
                 bootAFound && !bootAWritable && bootABase == kExpectedBootABase && bootASize == kExpectedBootASize &&
                 bootBFound && !bootBWritable && bootBBase == kExpectedBootBBase && bootBSize == kExpectedBootBSize &&
                 rwOpenRefused && mediaReadOk && (xring_ufs_block_errors == 0ULL);

    if (!allOk) {
        kprintf("[XRING_UFS_BLK] FAIL: dir_wr_rej=%u(0x%x) whole=%u parts=%u user=%u bootA=%u bootB=%u rw_ref=%u rd_ok=%u reads=%llu blks=%llu w_rej=%llu err=%llu\n",
                directWriteRejected ? 1u : 0u, static_cast<unsigned>(writeRejRc),
                wholeFound ? 1u : 0u, childPartitions, userFound ? 1u : 0u, bootAFound ? 1u : 0u, bootBFound ? 1u : 0u,
                rwOpenRefused ? 1u : 0u, mediaReadOk ? 1u : 0u,
                static_cast<unsigned long long>(xring_ufs_block_reads),
                static_cast<unsigned long long>(xring_ufs_block_read_blocks),
                static_cast<unsigned long long>(xring_ufs_block_write_rejects),
                static_cast<unsigned long long>(xring_ufs_block_errors));
        return;
    }

    kprintf("[XRING_UFS_BLK] PASS: whole=%s(528GB,ro) parts=%u userdata=%s boot_a=%s(ANDROID!v%u,%u) reads=%llu blks=%llu w_rej=%llu rw_ref=1 err=0\n",
            wholeBsd, childPartitions, userBsd, bootABsd, bootHdrVer, bootKernelSz,
            static_cast<unsigned long long>(xring_ufs_block_reads),
            static_cast<unsigned long long>(xring_ufs_block_read_blocks),
            static_cast<unsigned long long>(xring_ufs_block_write_rejects));
}
