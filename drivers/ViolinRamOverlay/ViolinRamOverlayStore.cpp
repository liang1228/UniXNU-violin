// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * ViolinRamOverlayStore — XNU in-DRAM sparse backing store for NativeRamBlock's
 * native_ufs_store_* persistence interface (Stage-8A).
 *
 * Allows mounting the 16 GiB logical APFS Data seed (data-24A446-16g-skipsetup.dbr)
 * through unmodified upstream NativeRamBlock (isBig + direct + writeBack) with ZERO
 * UFS writes, bounded DRAM usage, and full thread safety via IORWLock.
 */

#include "ViolinRamOverlayCore.h"

#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <pexpert/pexpert.h>

extern "C" {
void kprintf(const char *fmt, ...);

/* Telemetry exported for [VIOLIN_HB] */
volatile uint64_t violin_ram_overlay_resident_pages = 0;
volatile uint64_t violin_ram_overlay_max_pages = 0;
volatile uint64_t violin_ram_overlay_reads = 0;
volatile uint64_t violin_ram_overlay_writes = 0;
volatile uint64_t violin_ram_overlay_cap_rejects = 0;
volatile uint32_t violin_ram_overlay_opened = 0;

unsigned native_ufs_store_mode(void);
int native_ufs_store_open(uint64_t blocks, uint64_t *first_lba, const char **why);
int native_ufs_store_read(uint64_t block, uint32_t count, void *dst);
int native_ufs_store_write(uint64_t block, uint32_t count, const void *src);
int native_ufs_store_write_cached(uint64_t block, uint32_t count, const void *src);
int native_ufs_store_sync(void);
unsigned native_ufs_store_gpt_check(void);
}

namespace {

struct KernelAlloc {
    void *allocZero(size_t bytes) { return IOMallocZero(bytes); }
    void freeMem(void *ptr, size_t bytes) { IOFree(ptr, bytes); }
};

static IORWLock *gOverlayLock = nullptr;
static violin_ram_overlay::Table gOverlayTable;
static KernelAlloc gKernelAlloc;

void ensureLock()
{
    if (__atomic_load_n(&gOverlayLock, __ATOMIC_ACQUIRE) != nullptr) {
        return;
    }
    IORWLock *fresh = IORWLockAlloc();
    IORWLock *expected = nullptr;
    if (!__atomic_compare_exchange_n(&gOverlayLock, &expected, fresh, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        if (fresh != nullptr) {
            IORWLockFree(fresh);
        }
    }
}

uint64_t configuredCapPages()
{
    uint32_t capMb = 1536U; /* Default 1.5 GiB ceiling out of 5 GiB XNU DRAM */
    PE_parse_boot_argn("violin-data-cap-mb", &capMb, sizeof(capMb));
    if (capMb < 64U) {
        capMb = 64U;
    } else if (capMb > 3072U) {
        capMb = 3072U;
    }
    return static_cast<uint64_t>(capMb) * 256ULL; /* 256 x 4 KiB pages per MiB */
}

bool overlayEnabled()
{
    uint32_t en = 1U;
    PE_parse_boot_argn("violin-ram-overlay", &en, sizeof(en));
    return en != 0U;
}

} // namespace

extern "C" {

unsigned native_ufs_store_mode(void)
{
    return overlayEnabled() ? 2U : 0U;
}

int native_ufs_store_open(uint64_t blocks, uint64_t *first_lba, const char **why)
{
    if (!overlayEnabled()) {
        if (why) *why = "violin-ram-overlay disabled";
        return 0;
    }
    ensureLock();
    if (gOverlayLock == nullptr) {
        if (why) *why = "overlay lock alloc failed";
        return 0;
    }

    const uint64_t capPages = configuredCapPages();
    IORWLockWrite(gOverlayLock);
    const bool ok = gOverlayTable.open(gKernelAlloc, blocks, capPages);
    if (ok) {
        violin_ram_overlay_max_pages = capPages;
        violin_ram_overlay_resident_pages = 0;
        violin_ram_overlay_reads = 0;
        violin_ram_overlay_writes = 0;
        violin_ram_overlay_cap_rejects = 0;
        __atomic_store_n(&violin_ram_overlay_opened, 1U, __ATOMIC_RELEASE);
    }
    IORWLockUnlock(gOverlayLock);

    if (!ok) {
        if (why) *why = "ViolinRamOverlayStore open failed";
        kprintf("[VIOLIN_OVL] FAIL open blocks=%llu cap_pages=%llu\n",
                static_cast<unsigned long long>(blocks),
                static_cast<unsigned long long>(capPages));
        return 0;
    }

    if (first_lba != nullptr) {
        *first_lba = 0ULL;
    }
    if (why != nullptr) {
        *why = "";
    }
    kprintf("[VIOLIN_OVL] OPEN PASS blocks=%llu (%llu MiB logical) cap=%llu pages (%llu MiB DRAM, 0 UFS writes)\n",
            static_cast<unsigned long long>(blocks),
            static_cast<unsigned long long>(blocks >> 8),
            static_cast<unsigned long long>(capPages),
            static_cast<unsigned long long>(capPages >> 8));
    return 1;
}

int native_ufs_store_read(uint64_t block, uint32_t count, void *dst)
{
    if (gOverlayLock == nullptr) {
        return 0;
    }
    IORWLockRead(gOverlayLock);
    const bool ok = gOverlayTable.read(block, count, dst);
    IORWLockUnlock(gOverlayLock);
    if (ok) {
        __atomic_fetch_add(&violin_ram_overlay_reads, count, __ATOMIC_RELAXED);
    }
    return ok ? 1 : 0;
}

int native_ufs_store_write(uint64_t block, uint32_t count, const void *src)
{
    if (gOverlayLock == nullptr) {
        return 0;
    }
    IORWLockWrite(gOverlayLock);
    const bool ok = gOverlayTable.write(gKernelAlloc, block, count, src);
    const uint64_t res = gOverlayTable.residentPages;
    const uint64_t rej = gOverlayTable.capRejects;
    IORWLockUnlock(gOverlayLock);

    __atomic_store_n(&violin_ram_overlay_resident_pages, res, __ATOMIC_RELAXED);
    __atomic_store_n(&violin_ram_overlay_cap_rejects, rej, __ATOMIC_RELAXED);
    if (ok) {
        __atomic_fetch_add(&violin_ram_overlay_writes, count, __ATOMIC_RELAXED);
    } else {
        kprintf("[VIOLIN_OVL] WRITE FAIL block=%llu count=%u res=%llu/%llu rej=%llu\n",
                static_cast<unsigned long long>(block), count,
                static_cast<unsigned long long>(res),
                static_cast<unsigned long long>(violin_ram_overlay_max_pages),
                static_cast<unsigned long long>(rej));
    }
    return ok ? 1 : 0;
}

int native_ufs_store_write_cached(uint64_t block, uint32_t count, const void *src)
{
    return native_ufs_store_write(block, count, src);
}

int native_ufs_store_sync(void)
{
    return __atomic_load_n(&violin_ram_overlay_opened, __ATOMIC_ACQUIRE) ? 1 : 0;
}

unsigned native_ufs_store_gpt_check(void)
{
    return 0U; /* Pure DRAM store: UFS GPT is untouched */
}

} // extern "C"
