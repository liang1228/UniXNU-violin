// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * ViolinStage8BCoordinator — Unified dual-mode storage coordinator for Stage-8B:
 *   - Live Dual-Boot D1 mode (xring-ufs-root=1):
 *       * Strictly read-only XringUfsRoot reading SHNGROOT v2 (OS + SystemOS +
 *         OS.vroot + SystemOS.vroot) from LUN 2's 128 GiB raw tail strictly after
 *         Android #80 userdata.
 *       * 16 GiB logical NativeRamBlock Data volume backed either by fenced
 *         persistent UFS 4.1 SHNGDATA (xring-ufs-data=2, LBA 99,382,264..103,576,696)
 *         or volatile DRAM ViolinRamOverlayStore (when xring-ufs-data=0).
 *       * Clean pre-reboot persistence commit via violin_storage_prepare_reboot()
 *         invoking NativeRamBlock::doSynchronizeCache() + UFS SYNCHRONIZE CACHE(10)
 *         + live GPT/SHNGROOT integrity verification.
 *   - QEMU Gate mode (stage7j-virtio=1):
 *       * Unmodified upstream NativeVirtioBlock + 16 GiB NativeRamBlock +
 *         ViolinRamOverlayStore using the identical sealed kernel binary.
 *   - Zero edits to upstream source/UniXNU.
 */

#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOService.h>
#include <IOKit/storage/IOBlockStorageDevice.h>
#include <IOKit/storage/IOMedia.h>
#include <kern/clock.h>
#include <kern/task.h>
#include <libkern/OSKextLib.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSIterator.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/libkern.h>
#include <pexpert/pexpert.h>
#include <sys/param.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>

#define NATIVE_VERIFIED_POLICY_HANDOFF 1
#include "VerifiedBlockPolicy.h"
#include "XringUfsRoot.h"

extern "C" {
void kprintf(const char *fmt, ...);

/* From KeyStoreGlue.cpp */
bool violin_keystore_init_and_selftest(void);

/* Globalized deferred static constructors (stripped from __mod_init_func). */
void violin_ioblockstoragedevice_static_init(void) __asm__("__GLOBAL__sub_I_IOBlockStorageDevice.cpp");
void violin_xringufsroot_static_init(void) __asm__("__GLOBAL__sub_I_XringUfsRoot.cpp");
void violin_nativeramblock_static_init(void) __asm__("__GLOBAL__sub_I_NativeRamBlock.cpp");
void violin_nativevirtioblock_static_init(void) __asm__("__GLOBAL__sub_I_NativeVirtioBlock.cpp");

/* From upstream NativeRamBlock.cpp */
extern volatile uint32_t native_ram_block_ready;
extern volatile uint64_t native_ram_block_bytes;
extern volatile uint64_t native_ram_block_reads;
extern volatile uint64_t native_ram_block_writes;
extern volatile uint64_t native_ram_block_failures;
extern volatile uint64_t native_ram_block_resident_bytes;
extern volatile uint32_t native_ram_block_sparse;
extern volatile uint32_t native_data_persist_state;
extern volatile uint32_t native_data_persist_header;
extern volatile uint32_t native_data_persist_gpt;
extern volatile uint32_t native_data_persist_gpt_after;
extern volatile uint32_t native_data_write_back;
extern volatile uint64_t native_data_persist_present;
extern volatile uint64_t native_data_persist_writes;
extern volatile uint64_t native_data_persist_syncs;
extern volatile uint64_t native_data_persist_errors;
extern volatile uint64_t native_data_flushes;
extern uint8_t native_ram_block_seed_sha256[32];
int native_ram_block_volume_device(const char *uuid, dev_t *device, char *path, size_t size);

/* From upstream NativeVirtioBlock.cpp */
extern volatile uint32_t native_virtio_ready;
extern volatile uint32_t native_virtio_verified_devices;
extern volatile uint32_t native_virtio_ambiguous_policies;
extern volatile uint64_t native_virtio_verified_blocks;
extern volatile uint32_t native_virtio_integrity_failures;
extern volatile uint32_t native_virtio_read_requests;
extern volatile uint32_t native_virtio_read_failures;
int native_verified_block_volume_device(const char *uuid, dev_t *device, char *path, size_t size);

/* Shared VerifiedRoot owner key (24A446 OS + SystemOS signed by this installation key) */
extern const uint8_t verified_root_key[395] = {
#include "stage7j_owner_key.inc"
};
extern const uint8_t verified_root_manifest[1] = {0};
extern const uint64_t verified_root_manifest_bytes = 0;
NativeVerifiedBlockPolicy verified_root_policies[16] = {};
uint64_t verified_root_policy_count = 0;

static const OSMetaClass *gParentBlockStorageMetaClass = nullptr;
static bool gStorageMetaClassesRegistered = false;
static IOBlockStorageDevice *gRamBlockDev = nullptr;

const OSMetaClass *native_source_storage_parent(void)
{
    return gParentBlockStorageMetaClass;
}

/* Optional loader-page release hook for NativeRamBlock weak_import */
bool ml_static_mfree_prepare(vm_offset_t, vm_size_t) { return false; }

void violin_storage_init(IOService *nub);
void violin_storage_prepare_reboot(void);
void violin_apfs_get_stats(uint64_t *ram_reads, uint64_t *ram_writes, uint64_t *ram_fail,
                           uint64_t *ram_bytes, uint64_t *ufs_wrej, uint64_t *ufs_err,
                           uint8_t seed_sha256_out[32]);
} // extern "C"

namespace {

constexpr const char *kOsVolumeUuid      = "2F8E6EED-68D5-4261-B8A3-12571BAA2DD4";
constexpr const char *kSysOsVolumeUuid   = "F914C62A-AD00-47C6-8281-5746291C339A";
constexpr const char *kData16gVolumeUuid = "984BC5BC-EEAE-4F31-A08C-B14E57FC3124";

constexpr uint64_t kPolicyMagic = 0x31504E494C4F4956ULL; /* "VIOLINP1" LE */
constexpr unsigned kVirtioQueueSize = 8u;
constexpr uint32_t kVirtioChunkBytes = 65536u;

struct PolicyEntry {
    uint64_t offset;
    uint64_t length;
};

struct PolicyHeader {
    uint64_t magic;
    uint64_t count;
    PolicyEntry entries[16];
};

struct VirtqDesc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
};

struct VirtBlkReq {
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
};

struct VirtqUsedElem {
    uint32_t id;
    uint32_t len;
};

inline void dmaBarrier() { __asm__ volatile("dmb osh" ::: "memory"); }

class TempVirtioReader {
    IOMemoryMap *map_ = nullptr;
    IOBufferMemoryDescriptor *qMem_ = nullptr;
    IOBufferMemoryDescriptor *tMem_ = nullptr;
    uintptr_t regs_ = 0;
    uint64_t qPa_ = 0;
    uint64_t tPa_ = 0;
    uint64_t capSectors_ = 0;
    uint16_t availIdx_ = 0;
    uint16_t usedIdx_ = 0;
    bool active_ = false;

    uint32_t rd32(uint32_t off) const {
        return *reinterpret_cast<volatile uint32_t *>(regs_ + off);
    }
    void wr32(uint32_t off, uint32_t v) const {
        *reinterpret_cast<volatile uint32_t *>(regs_ + off) = v;
        __asm__ volatile("dsb oshst" ::: "memory");
    }
    void wr64(uint32_t off, uint64_t v) const {
        wr32(off, static_cast<uint32_t>(v));
        wr32(off + 4u, static_cast<uint32_t>(v >> 32));
    }

public:
    ~TempVirtioReader() { close(); }
    uint64_t capacityBytes() const { return capSectors_ * 512ULL; }
    uint64_t mmioPa() const { return map_ ? map_->getPhysicalAddress() : 0ULL; }

    bool open(IOService *provider) {
        if (!provider || provider->getResources() != kIOReturnSuccess) return false;
        map_ = provider->mapDeviceMemoryWithIndex(0, kIOMapAnywhere | kIOMapInhibitCache);
        if (!map_ || map_->getLength() < 0x108u) { close(); return false; }
        regs_ = static_cast<uintptr_t>(map_->getVirtualAddress());
        if (rd32(0x00) != 0x74726976u || rd32(0x04) != 2u || rd32(0x08) != 2u) {
            close();
            return false;
        }
        wr32(0x70, 0);
        for (unsigned i = 0; i < 10000u && rd32(0x70) != 0u; ++i) IODelay(1);
        if (rd32(0x70) != 0u) { close(); return false; }

        wr32(0x70, 1);
        wr32(0x70, 3);
        wr32(0x14, 0);
        uint32_t fLo = rd32(0x10);
        wr32(0x14, 1);
        uint32_t fHi = rd32(0x10);
        if (!(fLo & (1u << 5)) || !(fHi & 1u)) { close(); return false; }

        wr32(0x24, 0);
        wr32(0x20, 1u << 5);
        wr32(0x24, 1);
        wr32(0x20, 1u);
        wr32(0x70, 11);
        if (!(rd32(0x70) & 8u)) { close(); return false; }

        wr32(0x30, 0);
        if (rd32(0x44) || rd32(0x34) < kVirtioQueueSize) { close(); return false; }

        qMem_ = IOBufferMemoryDescriptor::inTaskWithOptions(
            kernel_task, kIODirectionInOut | kIOMemoryPhysicallyContiguous, 4096, 4096);
        tMem_ = IOBufferMemoryDescriptor::inTaskWithOptions(
            kernel_task, kIODirectionInOut | kIOMemoryPhysicallyContiguous, kVirtioChunkBytes, 4096);
        if (!qMem_ || !tMem_) { close(); return false; }

        IOByteCount qLen = 0, tLen = 0;
        qPa_ = qMem_->getPhysicalSegment(0, &qLen);
        tPa_ = tMem_->getPhysicalSegment(0, &tLen);
        if (!qPa_ || !tPa_ || qLen < 4096u || tLen < kVirtioChunkBytes) { close(); return false; }

        bzero(qMem_->getBytesNoCopy(), 4096);
        *reinterpret_cast<volatile uint16_t *>(static_cast<uint8_t *>(qMem_->getBytesNoCopy()) + 128) = 1;
        availIdx_ = usedIdx_ = 0;
        dmaBarrier();

        wr32(0x38, kVirtioQueueSize);
        wr64(0x80, qPa_);
        wr64(0x90, qPa_ + 128);
        wr64(0xa0, qPa_ + 256);
        wr32(0x44, 1);

        capSectors_ = static_cast<uint64_t>(rd32(0x100)) | (static_cast<uint64_t>(rd32(0x104)) << 32);
        wr32(0x70, 15);
        active_ = (rd32(0x70) & 15u) == 15u;
        if (!active_) { close(); return false; }
        return true;
    }

    bool readSectors(uint64_t sector, uint32_t bytes, void *dst) {
        if (!active_ || !bytes || bytes > kVirtioChunkBytes || (bytes & 511u)) return false;
        auto *q = static_cast<uint8_t *>(qMem_->getBytesNoCopy());
        auto *desc = reinterpret_cast<VirtqDesc *>(q);
        auto *req = reinterpret_cast<VirtBlkReq *>(q + 512);
        volatile uint8_t *st = q + 528;
        *req = {0u, 0u, sector};
        *st = 0xffu;
        desc[0] = {qPa_ + 512, sizeof(VirtBlkReq), 1, 1};
        desc[1] = {tPa_, bytes, 3, 2};
        desc[2] = {qPa_ + 528, 1, 2, 0};

        auto *avail = reinterpret_cast<volatile uint16_t *>(q + 128);
        avail[2 + (availIdx_ % kVirtioQueueSize)] = 0;
        dmaBarrier();
        ++availIdx_;
        avail[1] = availIdx_;
        dmaBarrier();
        wr32(0x50, 0);

        auto *used = reinterpret_cast<volatile uint16_t *>(q + 256);
        uint64_t deadline = 0;
        clock_interval_to_deadline(2000u, kMillisecondScale, &deadline);
        while (used[1] == usedIdx_) {
            if (mach_absolute_time() >= deadline) return false;
            dmaBarrier();
            IODelay(1);
        }
        dmaBarrier();
        auto *elem = reinterpret_cast<volatile VirtqUsedElem *>(q + 260) + (usedIdx_ % kVirtioQueueSize);
        bool ok = (used[1] == static_cast<uint16_t>(usedIdx_ + 1)) &&
                  elem->id == 0 && elem->len >= bytes + 1 && *st == 0;
        ++usedIdx_;
        uint32_t intr = rd32(0x60) & 3u;
        if (intr) wr32(0x64, intr);
        if (!ok) return false;
        memcpy(dst, tMem_->getBytesNoCopy(), bytes);
        return true;
    }

    void close() {
        if (regs_ && active_) {
            wr32(0x70, 0);
            for (unsigned i = 0; i < 10000u && rd32(0x70) != 0u; ++i) IODelay(1);
        }
        active_ = false;
        regs_ = 0;
        if (tMem_) { tMem_->release(); tMem_ = nullptr; }
        if (qMem_) { qMem_->release(); qMem_ = nullptr; }
        if (map_)  { map_->release();  map_ = nullptr; }
    }
};

bool ensureStorageMetaClassesRegistered()
{
    if (gStorageMetaClassesRegistered) return true;

    OSReturn kextRc = OSKextLoadKextWithIdentifier("com.apple.iokit.IOStorageFamily");
    const OSSymbol *baseSym = OSSymbol::withCStringNoCopy("IOBlockStorageDevice");
    const OSMetaClass *parentMc = baseSym ? OSMetaClass::getMetaClassWithName(baseSym) : nullptr;
    if (baseSym) baseSym->release();
    kprintf("[VIOLIN_8B] IOStorageFamily load=0x%x parent_mc=%p(%s,sz=%u)\n",
            static_cast<unsigned>(kextRc), parentMc,
            parentMc ? parentMc->getClassName() : "<null>",
            parentMc ? parentMc->getClassSize() : 0u);
    if (kextRc != kOSReturnSuccess || !parentMc) return false;

    gParentBlockStorageMetaClass = parentMc;
    void *loadHandle = OSMetaClass::preModLoad("com.apple.iokit.IOStorageFamily");
    if (!loadHandle) return false;

    violin_ioblockstoragedevice_static_init();
    violin_xringufsroot_static_init();
    violin_nativeramblock_static_init();
    violin_nativevirtioblock_static_init();

    OSReturn postRc = OSMetaClass::postModLoad(loadHandle);
    kprintf("[VIOLIN_8B] late metaclass postModLoad rc=0x%x\n", static_cast<unsigned>(postRc));
    if (postRc != kOSReturnSuccess) return false;

    gStorageMetaClassesRegistered = true;
    return true;
}

void startRamDataVolume(IOService *nub)
{
    IOService *ramProv = nub ? nub->getProvider() : nullptr;
    if (!ramProv) ramProv = IOService::getPlatform();
    if (!ramProv) return;
    OSObject *obj = OSMetaClass::allocClassWithName("NativeRamBlock");
    IOService *ramDev = OSDynamicCast(IOService, obj);
    if (ramDev && ramDev->init() && ramDev->attach(ramProv) && ramDev->start(ramProv)) {
        IOBlockStorageDevice *blkDev = OSDynamicCast(IOBlockStorageDevice, ramDev);
        if (blkDev != nullptr) {
            blkDev->retain();
            __atomic_store_n(&gRamBlockDev, blkDev, __ATOMIC_RELEASE);
        }
        kprintf("[VIOLIN_8B_RAM] started NativeRamBlock bytes=%llu (%llu MiB) resident=%llu sparse=%u ovl_state=%u hdr=%u wb=%u pres=%llu\n",
                static_cast<unsigned long long>(native_ram_block_bytes),
                static_cast<unsigned long long>(native_ram_block_bytes >> 20),
                static_cast<unsigned long long>(native_ram_block_resident_bytes),
                native_ram_block_sparse,
                native_data_persist_state,
                native_data_persist_header,
                native_data_write_back,
                static_cast<unsigned long long>(native_data_persist_present));
    } else {
        if (ramDev) { ramDev->detach(ramProv); ramDev->release(); }
        else if (obj) { obj->release(); }
        kprintf("[VIOLIN_8B_RAM] FAIL: NativeRamBlock attach/start failed\n");
    }
}

void waitVolumes(const char *tag)
{
    dev_t osDev = NODEV, sysDev = NODEV, dataDev = NODEV;
    char osPath[64] = {}, sysPath[64] = {}, dataPath[64] = {};
    bool osOk = false, sysOk = false, dataOk = false;
    uint64_t deadline = 0;
    clock_interval_to_deadline(20000u, kMillisecondScale, &deadline);
    while (true) {
        if (!osOk) {
            osOk = native_verified_block_volume_device(kOsVolumeUuid, &osDev, osPath, sizeof(osPath)) != 0;
        }
        if (!sysOk) {
            sysOk = native_verified_block_volume_device(kSysOsVolumeUuid, &sysDev, sysPath, sizeof(sysPath)) != 0;
        }
        if (!dataOk) {
            dataOk = native_ram_block_volume_device(kData16gVolumeUuid, &dataDev, dataPath, sizeof(dataPath)) != 0;
        }
        if (osOk && sysOk && dataOk) break;
        if (mach_absolute_time() >= deadline) break;
        IOSleep(100u);
    }

    kprintf("[%s] %s: os=%s(%u) sysos=%s(%u) data=%s(%u) data_bytes=%lluMiB\n",
            tag,
            (osOk && sysOk && dataOk) ? "PASS" : "INCOMPLETE",
            osOk ? osPath : "<none>", osOk ? 1u : 0u,
            sysOk ? sysPath : "<none>", sysOk ? 1u : 0u,
            dataOk ? dataPath : "<none>", dataOk ? 1u : 0u,
            static_cast<unsigned long long>(native_ram_block_bytes >> 20));
    kprintf("[%s_PERSIST] ovl_state=%u hdr=%u wb=%u pres=%llu gpt=0x%x/0x%x sdata_open=%u sdata_lba=%llu\n",
            tag,
            native_data_persist_state,
            native_data_persist_header,
            native_data_write_back,
            static_cast<unsigned long long>(native_data_persist_present),
            native_data_persist_gpt,
            native_data_persist_gpt_after,
            xring_ufs_data_open_ok,
            static_cast<unsigned long long>(xring_ufs_data_first_lba));
}

void dualboot_d1_ufs_init(IOService *nub)
{
    if (!ensureStorageMetaClassesRegistered()) {
        kprintf("[VIOLIN_8B] FAIL: storage metaclass registration failed\n");
        return;
    }
    OSReturn apfsRc = OSKextLoadKextWithIdentifier("com.apple.filesystems.apfs");
    kprintf("[VIOLIN_8B] apfs kext load=0x%x\n", static_cast<unsigned>(apfsRc));

    IOService *prov = nub ? nub->getProvider() : nullptr;
    if (!prov) prov = IOService::getPlatform();
    if (!xring_ufs_root_start(prov)) {
        kprintf("[VIOLIN_8B] FAIL: xring_ufs_root_start failed\n");
        return;
    }

    startRamDataVolume(nub);
    waitVolumes("VIOLIN_8B_UFS");
    kprintf("[VIOLIN_D1_STORAGE] ufs_win=%u vblocks=%llu ifail=%u rfail=%llu wrej=%llu sdata=(m=%u,ok=%u,lba=%llu,blks=%llu)\n",
            xring_ufs_root_windows,
            static_cast<unsigned long long>(xring_ufs_root_verified_blocks),
            xring_ufs_root_integrity_failures,
            static_cast<unsigned long long>(xring_ufs_root_read_failures),
            static_cast<unsigned long long>(xring_ufs_root_write_rejects),
            xring_ufs_data_mode_active,
            xring_ufs_data_open_ok,
            static_cast<unsigned long long>(xring_ufs_data_first_lba),
            static_cast<unsigned long long>(xring_ufs_data_blocks));
}

void qemu_virtio_init(IOService *nub)
{
    if (!ensureStorageMetaClassesRegistered()) {
        kprintf("[VIOLIN_8B_QEMU] FAIL: storage metaclass registration failed\n");
        return;
    }
    OSReturn apfsRc = OSKextLoadKextWithIdentifier("com.apple.filesystems.apfs");
    kprintf("[VIOLIN_8B_QEMU] apfs kext load=0x%x\n", static_cast<unsigned>(apfsRc));

    IORegistryEntry *armIo = IORegistryEntry::fromPath("/arm-io", gIODTPlane);
    if (!armIo) {
        kprintf("[VIOLIN_8B_QEMU] FAIL: /arm-io not found\n");
        return;
    }

    IOService *dataProviders[8] = {};
    unsigned dataProviderCount = 0;
    vm_offset_t tempBufs[16] = {};
    vm_size_t tempSizes[16] = {};
    unsigned tempCount = 0;

    OSIterator *it = armIo->getChildIterator(gIODTPlane);
    if (it) {
        while (OSObject *obj = it->getNextObject()) {
            IOService *child = OSDynamicCast(IOService, obj);
            if (!child) continue;
            OSData *compat = OSDynamicCast(OSData, child->getProperty("compatible"));
            if (!compat || compat->getLength() < 12u ||
                memcmp(compat->getBytesNoCopy(), "virtio,mmio", 12u) != 0) {
                continue;
            }
            TempVirtioReader reader;
            if (!reader.open(child)) continue;

            uint8_t sec0[512] = {};
            bool rdOk = reader.readSectors(0, 512, sec0);
            PolicyHeader hdr = {};
            if (rdOk) memcpy(&hdr, sec0, sizeof(hdr));

            if (rdOk && hdr.magic == kPolicyMagic && hdr.count >= 1u && hdr.count <= 8u) {
                for (unsigned idx = 0; idx < hdr.count; ++idx) {
                    uint64_t off = hdr.entries[idx].offset;
                    uint64_t len = hdr.entries[idx].length;
                    if ((off & 511u) != 0u || len == 0u || len > 128ULL * 1024ULL * 1024ULL) break;
                    vm_size_t allocSz = round_page(static_cast<vm_size_t>(len));
                    vm_offset_t mem = 0;
                    if (kmem_alloc(kernel_map, &mem, allocSz,
                                   static_cast<kma_flags_t>(KMA_KOBJECT | KMA_DATA),
                                   VM_KERN_MEMORY_SECURITY) != KERN_SUCCESS) break;
                    uint8_t *dst = reinterpret_cast<uint8_t *>(mem);
                    uint64_t done = 0;
                    bool copyOk = true;
                    while (done < len) {
                        uint64_t rem = len - done;
                        uint32_t toRead = rem > kVirtioChunkBytes ? kVirtioChunkBytes : static_cast<uint32_t>(rem);
                        uint32_t alignedRead = (toRead + 511u) & ~511u;
                        if (done + alignedRead <= allocSz) {
                            if (!reader.readSectors((off + done) / 512ULL, alignedRead, dst + done)) { copyOk = false; break; }
                        } else {
                            static uint8_t tailBuf[kVirtioChunkBytes];
                            if (!reader.readSectors((off + done) / 512ULL, alignedRead, tailBuf)) { copyOk = false; break; }
                            memcpy(dst + done, tailBuf, toRead);
                        }
                        done += toRead;
                    }
                    if (!copyOk) { kmem_free(kernel_map, mem, allocSz); break; }
                    tempBufs[tempCount] = mem;
                    tempSizes[tempCount] = allocSz;
                    verified_root_policies[tempCount].manifest = dst;
                    verified_root_policies[tempCount].manifestBytes = len;
                    ++tempCount;
                }
                verified_root_policy_count = tempCount;
                reader.close();
            } else {
                reader.close();
                if (dataProviderCount < 8u) {
                    child->retain();
                    dataProviders[dataProviderCount++] = child;
                }
            }
        }
        it->release();
    }
    armIo->release();

    for (unsigned i = 0; i < dataProviderCount; ++i) {
        IOService *prov = dataProviders[i];
        OSObject *obj = OSMetaClass::allocClassWithName("NativeVirtioBlock");
        IOService *blk = OSDynamicCast(IOService, obj);
        if (blk && blk->init() && blk->attach(prov) && blk->start(prov)) {
            kprintf("[VIOLIN_8B_QEMU] virtio disk[%u] ready verified=%u\n", i, native_virtio_verified_devices);
        } else {
            if (blk) { blk->detach(prov); blk->release(); }
            else if (obj) { obj->release(); }
        }
        prov->release();
    }

    verified_root_policy_count = 0;
    for (unsigned i = 0; i < tempCount; ++i) {
        verified_root_policies[i].manifest = nullptr;
        verified_root_policies[i].manifestBytes = 0;
        if (tempBufs[i]) kmem_free(kernel_map, tempBufs[i], tempSizes[i]);
    }

    startRamDataVolume(nub);
    waitVolumes("VIOLIN_8B_QEMU");
}

} // namespace

extern "C" void violin_storage_prepare_reboot(void)
{
    IOBlockStorageDevice *blkDev = __atomic_load_n(&gRamBlockDev, __ATOMIC_ACQUIRE);
    IOReturn blkRc = kIOReturnNotFound;
    if (blkDev != nullptr) {
        blkRc = blkDev->doSynchronizeCache();
    }
    if (xring_ufs_data_open_ok != 0U) {
        int ufsSync = xring_ufs_data_store_sync();
        unsigned gptAfter = xring_ufs_data_store_gpt_check();
        kprintf("[VIOLIN_PERSIST_SYNC] mode=ufs blk_sync=0x%x ufs_sync=%d gpt_after=0x%x ovl_state=%u pres=%llu fl=%llu\n",
                static_cast<unsigned>(blkRc), ufsSync, gptAfter,
                native_data_persist_state,
                static_cast<unsigned long long>(native_data_persist_present),
                static_cast<unsigned long long>(native_data_flushes));
        kprintf("[VIOLIN_PERSIST_SYNC2] pwr=%llu psy=%llu perr=%llu sdata=(rd=%llu,wf=%llu,wc=%llu,sy=%llu,err=%llu,wrej=%llu)\n",
                static_cast<unsigned long long>(native_data_persist_writes),
                static_cast<unsigned long long>(native_data_persist_syncs),
                static_cast<unsigned long long>(native_data_persist_errors),
                static_cast<unsigned long long>(xring_ufs_data_reads),
                static_cast<unsigned long long>(xring_ufs_data_writes_fua),
                static_cast<unsigned long long>(xring_ufs_data_writes_cached),
                static_cast<unsigned long long>(xring_ufs_data_syncs),
                static_cast<unsigned long long>(xring_ufs_data_errors),
                static_cast<unsigned long long>(xring_ufs_data_write_rejects));
    } else {
        kprintf("[VIOLIN_PERSIST_SYNC] mode=ram blk_sync=0x%x ovl_state=%u pres=%llu fl=%llu\n",
                static_cast<unsigned>(blkRc),
                native_data_persist_state,
                static_cast<unsigned long long>(native_data_persist_present),
                static_cast<unsigned long long>(native_data_flushes));
    }
}

extern "C" void violin_apfs_get_stats(uint64_t *ram_reads, uint64_t *ram_writes, uint64_t *ram_fail,
                                      uint64_t *ram_bytes, uint64_t *ufs_wrej, uint64_t *ufs_err,
                                      uint8_t seed_sha256_out[32])
{
    if (ram_reads)  *ram_reads  = native_ram_block_reads;
    if (ram_writes) *ram_writes = native_ram_block_writes;
    if (ram_fail)   *ram_fail   = native_ram_block_failures;
    if (ram_bytes)  *ram_bytes  = native_ram_block_bytes;
    if (ufs_wrej)   *ufs_wrej   = xring_ufs_root_write_rejects;
    if (ufs_err)    *ufs_err    = xring_ufs_root_read_failures;
    if (seed_sha256_out) {
        memcpy(seed_sha256_out, native_ram_block_seed_sha256, 32u);
    }
}

extern "C" void violin_storage_init(IOService *nub)
{
    OSReturn hidRc = OSKextLoadKextWithIdentifier("com.apple.iokit.IOHIDFamily");
    kprintf("[VIOLIN_8B] IOHIDFamily load=0x%x\n", static_cast<unsigned>(hidRc));
    (void)violin_keystore_init_and_selftest();
    uint32_t ufsEn = 0u, virtioEn = 0u;
    if (PE_parse_boot_argn("xring-ufs-root", &ufsEn, sizeof(ufsEn)) && ufsEn == 1u) {
        dualboot_d1_ufs_init(nub);
    } else if (PE_parse_boot_argn("stage7j-virtio", &virtioEn, sizeof(virtioEn)) && virtioEn == 1u) {
        qemu_virtio_init(nub);
    }
}
