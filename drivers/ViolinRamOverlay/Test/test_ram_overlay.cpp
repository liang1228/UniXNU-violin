// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * Host ASan/UBSan TDD suite for ViolinRamOverlayCore + unmodified upstream PersistOverlay.h.
 */

#include "ViolinRamOverlayCore.h"
#include "PersistOverlay.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace {

struct CountingAlloc {
    size_t liveBytes = 0;
    size_t liveAllocs = 0;
    size_t peakBytes = 0;
    bool failNext = false;

    void *allocZero(size_t bytes)
    {
        if (failNext) {
            failNext = false;
            return nullptr;
        }
        void *p = calloc(1, bytes);
        assert(p != nullptr);
        liveBytes += bytes;
        ++liveAllocs;
        if (liveBytes > peakBytes) {
            peakBytes = liveBytes;
        }
        return p;
    }

    void freeMem(void *ptr, size_t bytes)
    {
        assert(ptr != nullptr);
        assert(liveBytes >= bytes);
        assert(liveAllocs > 0);
        liveBytes -= bytes;
        --liveAllocs;
        free(ptr);
    }
};

struct OverlayOps {
    violin_ram_overlay::Table *table;
    CountingAlloc *alloc;
    uint64_t syncCount = 0;

    bool read(uint64_t b, uint32_t n, void *dst) { return table->read(b, n, dst); }
    bool write(uint64_t b, uint32_t n, const void *src) { return table->write(*alloc, b, n, src); }
    bool sync() { ++syncCount; return true; }
};

void testCoreBasicsAndZeroElision()
{
    CountingAlloc alloc;
    violin_ram_overlay::Table t;

    assert(!t.open(alloc, 0, 10));
    assert(!t.open(alloc, violin_ram_overlay::kMaxTotalBlocks + 1, 10));
    assert(!t.open(alloc, 100, 0));

    assert(t.open(alloc, 4096, 4));

    uint8_t zero[4096] = {};
    uint8_t buf[4096];
    memset(buf, 0xAA, sizeof(buf));

    /* Unwritten blocks read as zero */
    assert(t.read(0, 1, buf));
    assert(memcmp(buf, zero, sizeof(buf)) == 0);

    /* Writing all-zero blocks allocates 0 pages */
    uint8_t zrun[4 * 4096] = {};
    assert(t.write(alloc, 1, 4, zrun));
    assert(t.residentPages == 0);
    assert(t.leafTables == 0);
    assert(t.zeroElided == 4);

    /* Write 3 distinct non-zero blocks across L2 boundaries */
    uint8_t p1[4096], p2[4096], p3[4096];
    memset(p1, 0x11, 4096);
    memset(p2, 0x22, 4096);
    memset(p3, 0x33, 4096);
    assert(t.write(alloc, 0, 1, p1));
    assert(t.write(alloc, 1024, 1, p2));
    assert(t.write(alloc, 4095, 1, p3));
    assert(t.residentPages == 3);
    assert(t.leafTables == 3);

    /* Overwrite existing block does not increase residentPages */
    memset(p1, 0x44, 4096);
    assert(t.write(alloc, 0, 1, p1));
    assert(t.residentPages == 3);

    /* Verify exact readback */
    assert(t.read(0, 1, buf) && memcmp(buf, p1, 4096) == 0);
    assert(t.read(1024, 1, buf) && memcmp(buf, p2, 4096) == 0);
    assert(t.read(4095, 1, buf) && memcmp(buf, p3, 4096) == 0);

    /* Atomic cap check: maxPages=4, resident=3 -> 2-block new write must fail atomically */
    uint8_t two[2 * 4096];
    memset(two, 0x55, sizeof(two));
    assert(!t.write(alloc, 10, 2, two));
    assert(t.residentPages == 3);
    assert(t.capRejects == 1);
    assert(t.read(10, 1, buf) && memcmp(buf, zero, 4096) == 0);

    /* Overwriting an allocated page with all zeros reclaims the page */
    assert(t.write(alloc, 1024, 1, zero));
    assert(t.residentPages == 2);
    assert(t.read(1024, 1, buf) && memcmp(buf, zero, 4096) == 0);

    /* Now 2-block new write succeeds (resident becomes 4 == maxPages) */
    assert(t.write(alloc, 10, 2, two));
    assert(t.residentPages == 4);

    /* Bounds overflow checks */
    assert(!t.read(4096, 1, buf));
    assert(!t.read(4095, 2, buf));
    assert(!t.read(UINT64_MAX, 1, buf));
    assert(!t.write(alloc, 4095, 2, two));
    assert(!t.write(alloc, 0, 0, p1));

    t.close(alloc);
    assert(alloc.liveBytes == 0 && alloc.liveAllocs == 0);
    printf("PASS: testCoreBasicsAndZeroElision\n");
}

void testPersistOverlay16GiBIntegration()
{
    CountingAlloc alloc;
    violin_ram_overlay::Table t;

    /* Exact 16 GiB APFS Data geometry matching data-24A446-16g-skipsetup.dbr */
    const uint64_t pages = (16ULL << 30) / 4096ULL; /* 4,194,304 */
    const uint64_t bb = persist::bitmapBlocks(pages); /* 128 */
    const uint64_t win = persist::windowBlocks(pages); /* 4,194,433 */
    assert(pages == 4194304ULL);
    assert(bb == 128ULL);
    assert(win == 4194433ULL);

    assert(t.open(alloc, win, 1024));

    uint8_t seed[32];
    for (int i = 0; i < 32; ++i) seed[i] = static_cast<uint8_t>(0xA0 + i);

    uint8_t *bitmap = static_cast<uint8_t *>(calloc(bb, persist::kBlock));
    uint8_t *dirty = static_cast<uint8_t *>(calloc(bb, 1));
    assert(bitmap && dirty);

    OverlayOps ops = {&t, &alloc, 0};
    persist::Overlay ov;

    /* Without reset=true, blank window returns Kept */
    assert(ov.open(ops, pages, seed, false, bitmap, false) == persist::Open::Kept);
    assert(!ov.active);
    assert(t.residentPages == 0);

    /* With reset=true (data-reset=1), formats 128 zero bitmap blocks (0 pages) + 1 header page */
    assert(ov.open(ops, pages, seed, false, bitmap, true) == persist::Open::Fresh);
    assert(ov.active);
    assert(t.residentPages == 1); /* Only SHNGDATA header block 0 is non-zero! */
    assert(t.zeroElided == 128);

    /* Enable write-back dirty tracking just like NativeRamBlock direct mode */
    ov.dirty = dirty;
    ov.dirtyBlocks = 0;

    /* Write runs near start, middle, and very end of 16 GiB logical space */
    uint8_t run[4 * 4096];
    for (size_t i = 0; i < sizeof(run); ++i) run[i] = static_cast<uint8_t>((i * 7 + 3) & 0xFF);
    assert(ov.writeRun(ops, 0, 4, run));
    assert(ov.writeRun(ops, 2000000ULL, 4, run));
    assert(ov.writeRun(ops, pages - 4, 4, run));
    assert(ov.present == 12);
    assert(ov.dirtyBlocks == 3);

    uint64_t flushedBlocks = 0;
    assert(ov.flush(ops, &flushedBlocks));
    assert(flushedBlocks == 3);
    assert(ov.dirtyBlocks == 0);
    /* 1 header + 3 non-zero bitmap blocks + 12 data pages = 16 pages total for 16 GiB logical! */
    assert(t.residentPages == 16);

    /* Re-open same overlay without reset -> Resumed with exact 12 present pages */
    memset(bitmap, 0, bb * persist::kBlock);
    persist::Overlay ov2;
    assert(ov2.open(ops, pages, seed, false, bitmap, false) == persist::Open::Resumed);
    assert(ov2.present == 12);
    assert(ov2.has(0) && ov2.has(3) && ov2.has(2000000ULL) && ov2.has(pages - 1));
    assert(!ov2.has(4) && !ov2.has(1999999ULL));

    /* Verify exact page data at tail of 16 GiB disk */
    uint8_t readback[4 * 4096] = {};
    assert(ops.read(persist::pageBlock(pages, pages - 4), 4, readback));
    assert(memcmp(readback, run, sizeof(run)) == 0);

    free(bitmap);
    free(dirty);
    t.close(alloc);
    assert(alloc.liveBytes == 0 && alloc.liveAllocs == 0);
    printf("PASS: testPersistOverlay16GiBIntegration (peak=%zu KiB for 16 GiB logical)\n",
           alloc.peakBytes / 1024);
}

} // namespace

int main()
{
    testCoreBasicsAndZeroElision();
    testPersistOverlay16GiBIntegration();
    printf("ALL ViolinRamOverlay HOST TDD CHECKS PASSED\n");
    return 0;
}
