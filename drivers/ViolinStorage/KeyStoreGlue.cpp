// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * KeyStoreGlue — Board glue & self-test for upstream AppleKeyStoreState
 * (source/UniXNU/drivers/AppleKeyStoreState/NativeKeyStoreEvents.cpp).
 *
 * Strictly zero upstream edits: provides the 6 extern "C" callbacks required
 * by NativeKeyStoreEvents.cpp, starts AppleKeyStore on IOPlatformExpert, and
 * exercises AppleKeyStoreUserClient (get_system, lock_state, device_state DER,
 * bag_uuid, software wrap/unwrap round-trip, and 1-byte tampered blob refusal).
 */

#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <kern/task.h>
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/libkern.h>
#include <pexpert/pexpert.h>

extern "C" {
void kprintf(const char *fmt, ...);

/* Provided by upstream NativeKeyStoreEvents.cpp */
IOService *native_keyevents_allocate(void);
size_t native_aks_encode_state(uint8_t *out, size_t capacity, uint32_t lockState);

volatile uint32_t violin_aks_ready = 0;
volatile uint32_t violin_aks_opens = 0;
volatile uint32_t violin_aks_refusals = 0;
volatile uint32_t violin_aks_calls = 0;
volatile uint32_t violin_aks_errors = 0;

void native_keyevents_open_refused(void)
{
    uint32_t n = __atomic_add_fetch(&violin_aks_refusals, 1u, __ATOMIC_RELAXED);
    if (n <= 4u) {
        kprintf("[VIOLIN_AKS] open refused #%u (aks=1 not enabled)\n", n);
    }
}

bool native_aks_state_enabled(void)
{
    uint32_t v = 0;
    return PE_parse_boot_argn("aks", &v, sizeof(v)) && v == 1u;
}

uint32_t native_aks_lock_state(void)
{
    uint32_t v = 3u; /* 3 = no passcode (default for bring-up) */
    if (PE_parse_boot_argn("aks-sls", &v, sizeof(v))) {
        if (v > 3u) {
            v = 3u;
        }
    }
    return v;
}

void native_aks_call(uint32_t selector, int32_t result)
{
    __atomic_fetch_add(&violin_aks_calls, 1u, __ATOMIC_RELAXED);
    if (result != 0) {
        __atomic_fetch_add(&violin_aks_errors, 1u, __ATOMIC_RELAXED);
    }
    (void)selector;
}

void native_aks_opened(void)
{
    __atomic_fetch_add(&violin_aks_opens, 1u, __ATOMIC_RELAXED);
}

size_t native_aks_device_id(uint8_t *out, size_t capacity)
{
    if (!out || capacity < 8u) {
        return 0u;
    }
    IORegistryEntry *chosen = IORegistryEntry::fromPath("/chosen", gIODTPlane);
    if (chosen) {
        OSData *ecid = OSDynamicCast(OSData, chosen->getProperty("unique-chip-id"));
        if (ecid && ecid->getLength() >= 8u) {
            size_t take = ecid->getLength();
            if (take > capacity) {
                take = capacity;
            }
            memcpy(out, ecid->getBytesNoCopy(), take);
            chosen->release();
            return take;
        }
        chosen->release();
    }
    /* Deterministic fallback when running under QEMU virt ADT without unique-chip-id. */
    static const uint8_t kFallbackId[8] = { 'V', 'I', 'O', 'L', 'I', 'N', '0', '1' };
    memcpy(out, kFallbackId, sizeof(kFallbackId));
    return sizeof(kFallbackId);
}

bool violin_keystore_init_and_selftest(void);
} // extern "C"

namespace {

IOService *gViolinKeyStore = nullptr;

void formatHex16(const uint8_t in[16], char out[33])
{
    static const char kHex[] = "0123456789abcdef";
    for (size_t i = 0; i < 16u; i++) {
        out[i * 2]     = kHex[(in[i] >> 4) & 0xFu];
        out[i * 2 + 1] = kHex[in[i] & 0xFu];
    }
    out[32] = '\0';
}

} // namespace

extern "C" bool violin_keystore_init_and_selftest(void)
{
    if (gViolinKeyStore != nullptr) {
        return true;
    }
    if (!native_aks_state_enabled()) {
        kprintf("[VIOLIN_AKS] skipped (aks=1 not set)\n");
        return false;
    }

    IOPlatformExpert *platform = IOService::getPlatform();
    if (!platform) {
        kprintf("[VIOLIN_AKS] FAIL: getPlatform() returned NULL\n");
        return false;
    }

    IOService *ks = native_keyevents_allocate();
    if (!ks || !ks->init()) {
        if (ks) ks->release();
        kprintf("[VIOLIN_AKS] FAIL: allocate/init AppleKeyStore failed\n");
        return false;
    }
    if (!ks->attach(platform) || !ks->start(platform)) {
        ks->detach(platform);
        ks->release();
        kprintf("[VIOLIN_AKS] FAIL: attach/start AppleKeyStore failed\n");
        return false;
    }
    gViolinKeyStore = ks;

    /* 1. Verify IORegistry matching and KeyOperationsAvailable property. */
    OSDictionary *match = IOService::serviceMatching("AppleKeyStore");
    IOService *found = match ? IOService::waitForMatchingService(match, 1000000000ULL) : nullptr;
    if (match) match->release();
    bool opsAvail = found && (found->getProperty("KeyOperationsAvailable") == kOSBooleanTrue);
    if (found) found->release();
    if (!opsAvail) {
        kprintf("[VIOLIN_AKS] FAIL: AppleKeyStore serviceMatching or KeyOperationsAvailable missing\n");
        return false;
    }

    /* 2. Open AppleKeyStoreUserClient and exercise core selectors. */
    IOUserClient *uc = nullptr;
    IOReturn rc = ks->newUserClient(kernel_task, nullptr, 0u, nullptr, &uc);
    if (rc != kIOReturnSuccess || !uc) {
        kprintf("[VIOLIN_AKS] FAIL: newUserClient rc=0x%x uc=%p\n", static_cast<unsigned>(rc), uc);
        return false;
    }

    /* sel 0: open handshake */
    IOExternalMethodArguments a0 = {};
    a0.version = kIOExternalMethodArgumentsCurrentVersion;
    IOReturn rc0 = uc->externalMethod(0u, &a0, nullptr, nullptr, nullptr);

    /* sel 14: aks_get_system -> scalar out 0 */
    uint64_t sysHandle = 0xDEADBEEFULL;
    IOExternalMethodArguments a14 = {};
    a14.version = kIOExternalMethodArgumentsCurrentVersion;
    a14.scalarOutput = &sysHandle;
    a14.scalarOutputCount = 1u;
    IOReturn rc14 = uc->externalMethod(14u, &a14, nullptr, nullptr, nullptr);

    /* sel 7: aks_get_lock_state(0) -> bit 2 (4 = unlocked since boot) */
    uint64_t devIn = 0u, lockOut = 0u;
    IOExternalMethodArguments a7 = {};
    a7.version = kIOExternalMethodArgumentsCurrentVersion;
    a7.scalarInput = &devIn;
    a7.scalarInputCount = 1u;
    a7.scalarOutput = &lockOut;
    a7.scalarOutputCount = 1u;
    IOReturn rc7 = uc->externalMethod(7u, &a7, nullptr, nullptr, nullptr);

    /* sel 17: aks_get_device_state -> DER matching native_aks_encode_state */
    uint8_t der[160] = {}, expectedDer[160] = {};
    uint32_t sls = native_aks_lock_state();
    size_t expDerLen = native_aks_encode_state(expectedDer, sizeof(expectedDer), sls);
    IOExternalMethodArguments a17 = {};
    a17.version = kIOExternalMethodArgumentsCurrentVersion;
    a17.scalarInput = &devIn;
    a17.scalarInputCount = 1u;
    a17.structureOutput = der;
    a17.structureOutputSize = sizeof(der);
    IOReturn rc17 = uc->externalMethod(17u, &a17, nullptr, nullptr, nullptr);
    bool derOk = (rc17 == kIOReturnSuccess) && (expDerLen > 16u) &&
                 (a17.structureOutputSize == expDerLen) && (der[0] == 0x31u) &&
                 (memcmp(der, expectedDer, expDerLen) == 0);

    /* sel 23: aks_get_bag_uuid -> 16-byte deterministic UUID */
    uint8_t bagUuid[16] = {};
    IOExternalMethodArguments a23 = {};
    a23.version = kIOExternalMethodArgumentsCurrentVersion;
    a23.scalarInput = &devIn;
    a23.scalarInputCount = 1u;
    a23.structureOutput = bagUuid;
    a23.structureOutputSize = sizeof(bagUuid);
    IOReturn rc23 = uc->externalMethod(23u, &a23, nullptr, nullptr, nullptr);
    uint8_t uuidOr = 0u;
    for (size_t i = 0; i < sizeof(bagUuid); i++) uuidOr |= bagUuid[i];
    bool uuidOk = (rc23 == kIOReturnSuccess) && (a23.structureOutputSize == 16u) && (uuidOr != 0u);

    /* sel 10: aks_wrap_key -> 8-byte tag + 32-byte ciphertext */
    uint8_t plain[32] = {};
    for (size_t i = 0; i < sizeof(plain); i++) plain[i] = static_cast<uint8_t>(0xA5u ^ (i * 13u));
    uint64_t wrapIn[2] = { 0u, 4u }; /* bag=0, class=4 */
    uint64_t wrapOutClass = 0u;
    uint8_t wrapped[64] = {};
    IOExternalMethodArguments a10 = {};
    a10.version = kIOExternalMethodArgumentsCurrentVersion;
    a10.scalarInput = wrapIn;
    a10.scalarInputCount = 2u;
    a10.scalarOutput = &wrapOutClass;
    a10.scalarOutputCount = 1u;
    a10.structureInput = plain;
    a10.structureInputSize = sizeof(plain);
    a10.structureOutput = wrapped;
    a10.structureOutputSize = sizeof(wrapped);
    IOReturn rc10 = uc->externalMethod(10u, &a10, nullptr, nullptr, nullptr);
    bool wrapOk = (rc10 == kIOReturnSuccess) && (wrapOutClass == 4u) &&
                  (a10.structureOutputSize == 40u) && (memcmp(wrapped + 8, plain, sizeof(plain)) != 0);

    /* sel 11: aks_unwrap_key -> exact plaintext round-trip */
    uint8_t unwrapped[64] = {};
    IOExternalMethodArguments a11 = {};
    a11.version = kIOExternalMethodArgumentsCurrentVersion;
    a11.scalarInput = wrapIn;
    a11.scalarInputCount = 2u;
    a11.structureInput = wrapped;
    a11.structureInputSize = a10.structureOutputSize;
    a11.structureOutput = unwrapped;
    a11.structureOutputSize = sizeof(unwrapped);
    IOReturn rc11 = uc->externalMethod(11u, &a11, nullptr, nullptr, nullptr);
    bool unwrapOk = wrapOk && (rc11 == kIOReturnSuccess) &&
                    (a11.structureOutputSize == sizeof(plain)) &&
                    (memcmp(unwrapped, plain, sizeof(plain)) == 0);

    /* Negative test: flip 1 bit in auth tag -> must refuse with 0xe00002bc */
    uint8_t tampered[40] = {};
    memcpy(tampered, wrapped, sizeof(tampered));
    tampered[0] ^= 0x01u;
    uint8_t badOut[64] = {};
    IOExternalMethodArguments a11Bad = {};
    a11Bad.version = kIOExternalMethodArgumentsCurrentVersion;
    a11Bad.scalarInput = wrapIn;
    a11Bad.scalarInputCount = 2u;
    a11Bad.structureInput = tampered;
    a11Bad.structureInputSize = sizeof(tampered);
    a11Bad.structureOutput = badOut;
    a11Bad.structureOutputSize = sizeof(badOut);
    IOReturn rc11Bad = uc->externalMethod(11u, &a11Bad, nullptr, nullptr, nullptr);
    bool tamperOk = (static_cast<uint32_t>(rc11Bad) == 0xe00002bcu);

    uc->clientClose();
    uc->release();

    char uuidHex[33] = {};
    formatHex16(bagUuid, uuidHex);

    bool allOk = (rc0 == kIOReturnSuccess) && (rc14 == kIOReturnSuccess && sysHandle == 0u) &&
                 (rc7 == kIOReturnSuccess && lockOut == 4u) && derOk && uuidOk && unwrapOk && tamperOk;
    if (!allOk) {
        kprintf("[VIOLIN_AKS] FAIL: rc0=0x%x rc14=0x%x(h=%llu) rc7=0x%x(l=%llu) der=%u uuid=%u wrap=%u unwrap=%u tamper=0x%x\n",
                static_cast<unsigned>(rc0), static_cast<unsigned>(rc14), static_cast<unsigned long long>(sysHandle),
                static_cast<unsigned>(rc7), static_cast<unsigned long long>(lockOut),
                derOk ? 1u : 0u, uuidOk ? 1u : 0u, wrapOk ? 1u : 0u, unwrapOk ? 1u : 0u,
                static_cast<unsigned>(rc11Bad));
        return false;
    }

    __atomic_store_n(&violin_aks_ready, 1u, __ATOMIC_RELEASE);
    kprintf("[VIOLIN_AKS] PASS: service=%p aks=1 sls=%u lock=0x%llx der=%zuB bag_uuid=%s wrap_unwrap=ok tamper_reject=0x%x calls=%u\n",
            ks, sls, static_cast<unsigned long long>(lockOut), expDerLen, uuidHex,
            static_cast<unsigned>(rc11Bad), violin_aks_calls);
    return true;
}
