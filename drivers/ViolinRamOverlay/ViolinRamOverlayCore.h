// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
/*
 * ViolinRamOverlayCore — Platform-independent sparse 2-level 4 KiB page-table store
 * implementing the block storage semantics expected by UniXNU PersistOverlay.h.
 *
 * Designed for Stage-8A (16 GiB logical APFS Data seed in DRAM with ZERO UFS writes):
 *   - Constant-time O(1) lookup via 2-level radix table (L1 -> 1024-entry L2 -> 4 KiB page).
 *   - All-zero block write elision & reclamation (PersistOverlay::open reset allocates 0 pages).
 *   - Strict overflow-safe bounds checks and atomic per-write memory ceiling enforcement.
 *   - Tested on Linux host with ASan + UBSan against unmodified upstream PersistOverlay.h.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace violin_ram_overlay {

constexpr uint32_t kBlockSize = 4096U;
constexpr uint32_t kLeafShift = 10U;
constexpr uint32_t kLeafSize = 1U << kLeafShift;
constexpr uint32_t kLeafMask = kLeafSize - 1U;
constexpr uint64_t kMaxTotalBlocks = (1ULL << 23); /* 32 GiB max logical window */

inline bool isAllZeroBlock(const uint8_t *block)
{
    uint64_t acc = 0ULL;
    for (size_t off = 0; off < kBlockSize; off += sizeof(uint64_t)) {
        uint64_t word = 0ULL;
        memcpy(&word, block + off, sizeof(word));
        acc |= word;
        if (acc != 0ULL) {
            return false;
        }
    }
    return true;
}

struct Table {
    uint8_t ***l1 = nullptr;
    uint64_t l1Count = 0;
    uint64_t totalBlocks = 0;
    uint64_t maxPages = 0;
    uint64_t residentPages = 0;
    uint64_t leafTables = 0;
    uint64_t readBlocks = 0;
    uint64_t writeBlocks = 0;
    uint64_t zeroElided = 0;
    uint64_t capRejects = 0;

    bool isOpen() const { return l1 != nullptr && totalBlocks > 0; }

    template <class Alloc>
    void close(Alloc &alloc)
    {
        if (l1 != nullptr) {
            for (uint64_t i = 0; i < l1Count; ++i) {
                uint8_t **leaf = l1[i];
                if (leaf == nullptr) {
                    continue;
                }
                for (uint32_t j = 0; j < kLeafSize; ++j) {
                    if (leaf[j] != nullptr) {
                        alloc.freeMem(leaf[j], kBlockSize);
                        leaf[j] = nullptr;
                    }
                }
                alloc.freeMem(leaf, kLeafSize * sizeof(uint8_t *));
                l1[i] = nullptr;
            }
            alloc.freeMem(l1, static_cast<size_t>(l1Count) * sizeof(uint8_t **));
            l1 = nullptr;
        }
        l1Count = 0;
        totalBlocks = 0;
        maxPages = 0;
        residentPages = 0;
        leafTables = 0;
    }

    template <class Alloc>
    bool open(Alloc &alloc, uint64_t blocks, uint64_t pageCap)
    {
        if (blocks == 0 || blocks > kMaxTotalBlocks || pageCap == 0) {
            return false;
        }
        close(alloc);
        const uint64_t nL1 = (blocks + kLeafSize - 1ULL) >> kLeafShift;
        void *mem = alloc.allocZero(static_cast<size_t>(nL1) * sizeof(uint8_t **));
        if (mem == nullptr) {
            return false;
        }
        l1 = static_cast<uint8_t ***>(mem);
        l1Count = nL1;
        totalBlocks = blocks;
        maxPages = pageCap;
        residentPages = 0;
        leafTables = 0;
        readBlocks = 0;
        writeBlocks = 0;
        zeroElided = 0;
        capRejects = 0;
        return true;
    }

    bool read(uint64_t block, uint32_t count, void *dst)
    {
        if (!isOpen() || dst == nullptr || count == 0 || block >= totalBlocks || count > totalBlocks - block) {
            return false;
        }
        uint8_t *out = static_cast<uint8_t *>(dst);
        for (uint32_t i = 0; i < count; ++i) {
            const uint64_t idx = block + i;
            uint8_t **leaf = l1[idx >> kLeafShift];
            uint8_t *page = leaf ? leaf[idx & kLeafMask] : nullptr;
            if (page != nullptr) {
                memcpy(out + static_cast<size_t>(i) * kBlockSize, page, kBlockSize);
            } else {
                memset(out + static_cast<size_t>(i) * kBlockSize, 0, kBlockSize);
            }
        }
        readBlocks += count;
        return true;
    }

    template <class Alloc>
    bool write(Alloc &alloc, uint64_t block, uint32_t count, const void *src)
    {
        if (!isOpen() || src == nullptr || count == 0 || block >= totalBlocks || count > totalBlocks - block) {
            return false;
        }
        const uint8_t *in = static_cast<const uint8_t *>(src);

        /* Pre-flight atomic capacity check across the entire multi-block run. */
        int64_t netNew = 0;
        for (uint32_t i = 0; i < count; ++i) {
            const uint64_t idx = block + i;
            const uint8_t *blk = in + static_cast<size_t>(i) * kBlockSize;
            uint8_t **leaf = l1[idx >> kLeafShift];
            const bool exists = (leaf != nullptr && leaf[idx & kLeafMask] != nullptr);
            const bool zero = isAllZeroBlock(blk);
            if (!exists && !zero) {
                ++netNew;
            } else if (exists && zero) {
                --netNew;
            }
        }
        if (netNew > 0 && static_cast<uint64_t>(netNew) > (maxPages - residentPages)) {
            ++capRejects;
            return false;
        }

        for (uint32_t i = 0; i < count; ++i) {
            const uint64_t idx = block + i;
            const uint64_t d1 = idx >> kLeafShift;
            const uint32_t d2 = static_cast<uint32_t>(idx & kLeafMask);
            const uint8_t *blk = in + static_cast<size_t>(i) * kBlockSize;

            if (isAllZeroBlock(blk)) {
                uint8_t **leaf = l1[d1];
                if (leaf != nullptr && leaf[d2] != nullptr) {
                    alloc.freeMem(leaf[d2], kBlockSize);
                    leaf[d2] = nullptr;
                    --residentPages;
                } else {
                    ++zeroElided;
                }
                continue;
            }

            uint8_t **leaf = l1[d1];
            if (leaf == nullptr) {
                void *lm = alloc.allocZero(kLeafSize * sizeof(uint8_t *));
                if (lm == nullptr) {
                    ++capRejects;
                    return false;
                }
                leaf = static_cast<uint8_t **>(lm);
                l1[d1] = leaf;
                ++leafTables;
            }
            uint8_t *page = leaf[d2];
            if (page == nullptr) {
                void *pm = alloc.allocZero(kBlockSize);
                if (pm == nullptr) {
                    ++capRejects;
                    return false;
                }
                page = static_cast<uint8_t *>(pm);
                leaf[d2] = page;
                ++residentPages;
            }
            memcpy(page, blk, kBlockSize);
        }
        writeBlocks += count;
        return true;
    }
};

} // namespace violin_ram_overlay
