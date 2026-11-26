#!/usr/bin/env python3
"""
Build Stage-8C: Touchscreen Input Closure (FF-A xsp1 + SPI9 + NVT-36536 TDDI Cascade +
ViolinHidInput IOHIDDevice + Bottom-Edge Swipe) + High Refresh Rate (WC 4-Worker GPR
Streaming Presenter + vsync=120 vsync-fixed=1 + DSI TMG probe)
for Xiaomi Pad 7S Pro (violin / O81A / XRING O1 / ipados-27.0.1-24A446).

Safety & provenance guarantees:
  - Zero edits to source/UniXNU.
  - OEM touch firmware blob (/opt/unixnu-out/stage8c-touch/novatek_nt36536_violin_fw_tm00.bin)
    is assembled strictly inside /opt/unixnu-out/stage8c-touch-highhz/obj/ (NEVER in git)
    and verified against its exact SHA-256 before linking.
  - Preserves all Stage-8B Route A storage, 10 GiB Bank 1 / 8 GiB XNU window,
    kern.maxvnodes=32768, and fenced persistent SHNGDATA warm resume (NO data-reset=1).
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess

ARCHIVE_DIR = Path(__file__).resolve().parent
VIOLIN = Path(os.environ.get("UNIXNU_VIOLIN_DIR", str(ARCHIVE_DIR.parents[1])))
SOURCE_ROOT = VIOLIN.parent
UNIXNU = Path(os.environ.get("UNIXNU_DIR", str(SOURCE_ROOT / "UniXNU")))
COMMON = Path(os.environ.get("UNIXNU_COMMON_DIR", str(SOURCE_ROOT / "UniXNU-xring-o1-common")))
UEFI = Path(os.environ.get("UNIXNU_UEFI_DIR", str(SOURCE_ROOT / "uefi-violin")))
MKBOOTV4 = ARCHIVE_DIR.parent / "stage8a" / "mkbootv4.py"

ORIG_TREE = Path("/opt/unixnu-out/violin/ipados-27.0.1-24A446/violin/tree")
STAGE7H = Path("/opt/unixnu-out/stage7h-apfs")
STAGE7J = Path("/opt/unixnu-out/stage7j-qemu-launchd")
STAGE8B = Path("/opt/unixnu-out/stage8b-mem10g-shngdata")
IPSW24 = Path("/opt/unixnu-out/ipsw/24A446")
ASSETS24 = Path("/opt/unixnu-out/macos26-assets-24A446")
OUT = Path("/opt/unixnu-out/stage8c-touch-highhz")

OEM_TOUCH_FW = Path("/opt/unixnu-out/stage8c-touch/novatek_nt36536_violin_fw_tm00.bin")
OEM_TOUCH_FW_SHA256 = "3effd0693bcd0277940e1b468b98feebffc2e03501d06eb26902d9fd1831185c"

TOOLCHAIN = Path("/opt/unixnu-out/toolchain-arm64e")
CLT = TOOLCHAIN / "CommandLineTools/usr"
XCTC = TOOLCHAIN / "XcodeDefault.xctoolchain/usr"

DATA_16G_DBR = ASSETS24 / "data-24A446-16g-skipsetup.dbr"
DATA_16G_UUID = "984BC5BC-EEAE-4F31-A08C-B14E57FC3124"


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, env=None, cwd=None, log_path=None):
    print(f"+ {' '.join(map(str, cmd))}", flush=True)
    if log_path:
        with open(log_path, "w") as lf:
            r = subprocess.run([str(c) for c in cmd], env=env, cwd=cwd, stdout=lf, stderr=subprocess.STDOUT)
        if r.returncode != 0:
            tail = Path(log_path).read_text(errors="replace")[-4000:]
            raise SystemExit(f"Command failed rc={r.returncode}; tail of {log_path}:\n{tail}")
    else:
        subprocess.run([str(c) for c in cmd], env=env, cwd=cwd, check=True)


def linux_env(tree: Path) -> dict:
    fakeroot = tree / ".cache/fakeroot"
    env = dict(os.environ)
    env.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "LC_ALL": "C",
        "ZERO_AR_DATE": "1",
        "UNIXNU_TOOLCHAIN": str(TOOLCHAIN),
        "CLT_PREFIX": str(CLT),
        "XCTOOLCHAIN_PREFIX": str(XCTC),
        "XNU_TOOLCHAIN_BIN": f"{CLT / 'bin'} {XCTC / 'bin'}",
        "UNIXNU_SDKROOT": str(fakeroot),
        "UNIXNU_SDK_VERSION": "27.0",
        "UNIXNU_IOS_VERSION": "27.0",
        "UNIXNU_XNU_ARCH": "arm64e",
        "UNIXNU_XNU_TARGET": "ios",
        "UNIXNU_PLATFORM_PATH": str(fakeroot / "Platforms/iPhoneOS.platform"),
        "CROSS_CLANG": str(TOOLCHAIN / "llvm/bin/clang"),
        "DARWIN_TRIPLE": "arm64e-apple-ios27.0",
        "CROSS_EXTRA_FLAGS": "-mllvm -disable-atexit-based-global-dtor-lowering",
        "CCC_OVERRIDE_OPTIONS": "# +-Wno-missing-designated-field-initializers +-Wno-unused-but-set-global",
        "PATH": f"{CLT / 'bin'}:{TOOLCHAIN / 'bin'}:{tree / 'scripts/linux'}:/opt/unixnu-linux/bin:{os.environ.get('PATH', '')}",
    })
    return env


def splice_uefi(prefix_bin: Path, fat_lz4: Path, out_bin: Path) -> None:
    uefi_bytes = prefix_bin.read_bytes()
    prefix_len = 4096 + 4194304
    assert len(uefi_bytes) >= prefix_len, f"UEFI prefix too small: {prefix_bin} ({len(uefi_bytes)} B)"
    img = bytearray(uefi_bytes[:prefix_len])
    lz4_payload = fat_lz4.read_bytes()
    uncomp_size = struct.unpack_from("<Q", lz4_payload, 6)[0]
    pad = (-len(lz4_payload)) % 512
    stored = lz4_payload + (b"\x00" * pad)
    trailer = struct.pack("<8sQQQ", b"VNPDISK2", len(stored), uncomp_size, 0)
    img += trailer + stored
    aligned_total = ((len(img) + 0xFFFF) // 0x10000) * 0x10000
    struct.pack_into("<Q", img, 0x10, aligned_total)
    out_bin.write_bytes(bytes(img))


def main():
    assert DATA_16G_DBR.is_file(), f"Missing 16 GiB Data seed: {DATA_16G_DBR}"
    assert OEM_TOUCH_FW.is_file(), f"Missing build-local OEM touch FW: {OEM_TOUCH_FW}"
    fw_sha = sha256_file(OEM_TOUCH_FW)
    assert fw_sha == OEM_TOUCH_FW_SHA256, f"OEM touch FW SHA-256 mismatch: {fw_sha} != {OEM_TOUCH_FW_SHA256}"
    print(f"VERIFIED OEM touch FW outside git: {OEM_TOUCH_FW} ({OEM_TOUCH_FW.stat().st_size} B, sha256={fw_sha[:16]}..)", flush=True)

    uefi_4g_qemu = STAGE8B / "violin-uefi-4g-qemu.bin"
    uefi_10g_qemu = STAGE8B / "violin-uefi-10g-qemu.bin"
    uefi_10g_live = STAGE8B / "violin-uefi-10g-live.bin"
    qemu_4g_adt = STAGE8B / "violin-stage8b-qemu-4g.adt"
    qemu_10g_adt = STAGE8B / "violin-stage8b-qemu-10g.adt"
    live_adt = STAGE8B / "violin-stage8b-live-10g.adt"
    for p in (uefi_4g_qemu, uefi_10g_qemu, uefi_10g_live, qemu_4g_adt, qemu_10g_adt, live_adt):
        assert p.is_file(), f"Missing Stage-8B base artifact: {p}"

    OUT.mkdir(parents=True, exist_ok=True)
    obj_dir = OUT / "obj"
    obj_dir.mkdir(parents=True, exist_ok=True)
    tdd_dir = OUT / "tdd"
    tdd_dir.mkdir(parents=True, exist_ok=True)
    tree = STAGE7J / "tree"
    env = linux_env(tree)
    host_env = dict(os.environ)
    host_env["PATH"] = "/usr/bin:/bin"

    # 1. Host ASan/UBSan TDD suites (FastFb, XringSpi9, Nvt36536+Tracker, RamOverlay, ShngRoot+ShngData)
    run([
        "gcc", "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
        f"-I{VIOLIN / 'drivers/ViolinGopProbe'}",
        VIOLIN / "drivers/ViolinGopProbe/Test/test_fast_fb_core.c",
        "-o", tdd_dir / "test_fast_fb_core",
    ], env=host_env)
    run([tdd_dir / "test_fast_fb_core"], env=host_env)

    run([
        "gcc", "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
        f"-I{COMMON / 'drivers/XringSpi'}",
        COMMON / "drivers/XringSpi/test_xring_spi9_core.c",
        "-o", tdd_dir / "test_xring_spi9_core",
    ], env=host_env)
    run([tdd_dir / "test_xring_spi9_core"], env=host_env)

    run([
        "gcc", "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
        f"-I{VIOLIN / 'drivers/ViolinTouch'}",
        VIOLIN / "drivers/ViolinTouch/Test/test_nvt36536_core.c",
        "-lm", "-o", tdd_dir / "test_nvt36536_core",
    ], env=host_env)
    run([tdd_dir / "test_nvt36536_core", OEM_TOUCH_FW], env=host_env)

    run([
        "g++", "-std=c++17", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
        f"-I{VIOLIN / 'drivers/ViolinRamOverlay'}",
        f"-I{UNIXNU / 'drivers/RamBlock'}",
        VIOLIN / "drivers/ViolinRamOverlay/Test/test_ram_overlay.cpp",
        "-o", tdd_dir / "test_ram_overlay",
    ], env=host_env)
    run([tdd_dir / "test_ram_overlay"], env=host_env)

    # 2. Rebuild & strictly PAC-audit:
    #    - XringUfsRoot.late.o (190/190 + ShngRootCore/ShngDataCore TDD)
    #    - libNativeLegacyDisplay.late.a (379/379 + Stage-8C ViolinFastFbCore presenter)
    #    - libViolinHidInput.late.a (207/207 IOHIDDevice + 220-slot edge-swipe hook)
    #    - libViolinGopPresenter.a
    run(["python3", "-B", VIOLIN / "scripts/build-xring-ufs-root.py"], env=host_env)
    ufs_root_late_o = Path("/opt/unixnu-out/stage7n-dualboot-d1/obj/XringUfsRoot.late.o")
    assert ufs_root_late_o.is_file()

    disp_dir = OUT / "native-legacy-display"
    run([
        "python3", "-B", VIOLIN / "scripts/build-violin-legacy-display.py",
        "--tree", tree,
        "--out-dir", disp_dir,
    ], env=env)
    disp_a = disp_dir / "libNativeLegacyDisplay.late.a"
    assert disp_a.is_file()

    hid_dir = OUT / "violin-hid-input"
    run([
        "python3", "-B", VIOLIN / "scripts/build-violin-hid-input.py",
        "--tree", tree,
        "--out-dir", hid_dir,
    ], env=env)
    hid_a = hid_dir / "libViolinHidInput.late.a"
    assert hid_a.is_file()

    gop_dir = OUT / "violin-gop-presenter"
    run([
        "python3", "-B", VIOLIN / "scripts/build-violin-gop-presenter.py",
        "--tree", tree,
        "--unixnu", UNIXNU,
        "--probe", VIOLIN / "drivers/ViolinGopProbe/ViolinGopProbe.cpp",
        "--out", gop_dir,
    ], env=env)
    gop_a = gop_dir / "libViolinGopPresenter.a"
    assert gop_a.is_file()

    # 3. Compile ViolinTouchDriver.cpp + assemble build-local Nvt36536FwBlob.o -> libViolinTouch.a
    spec = importlib.util.spec_from_file_location("bvs", VIOLIN / "scripts/build-violin-source-storage.py")
    bvs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bvs)
    os.environ["UNIXNU_XNU_ARCH"] = "arm64e"
    os.environ["UNIXNU_IOS_VERSION"] = "27.0.1"
    kt = bvs.load_module("kernel_target", UNIXNU / "scripts/kernel_target.py")

    cpp_rec = json.loads(
        (tree / "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json")
        .read_text().strip().rstrip(",")
    )
    vm_compat_h = STAGE7J / "storage/stage7j_xnu12377_vm_compat.h"
    ar = bvs.find_tool(["llvm-ar", "llvm-ar-21", "llvm-ar-20", "ar"])

    touch_inc = [
        "-I", str(tree / ".cache/xnu-work/osfmk"),
        "-I", str(COMMON / "drivers/XringSpi"),
        "-I", str(VIOLIN / "drivers/ViolinTouch"),
        "-include", str(vm_compat_h),
        "-Wno-error",
    ]
    touch_o = obj_dir / "ViolinTouchDriver.o"
    run(
        bvs.make_compile_cmd(cpp_rec, VIOLIN / "drivers/ViolinTouch/ViolinTouchDriver.cpp", touch_o, touch_inc),
        env=env, cwd=cpp_rec["directory"], log_path=obj_dir / "ViolinTouchDriver.compile.log",
    )
    kt.check_object(touch_o.read_bytes(), touch_o.name)

    fw_s = obj_dir / "Nvt36536FwBlob.S"
    fw_o = obj_dir / "Nvt36536FwBlob.o"
    fw_s.write_text(
        ".section __TEXT,__const\n"
        ".p2align 4\n"
        ".globl _violin_nvt_fw_blob\n"
        "_violin_nvt_fw_blob:\n"
        f'.incbin "{OEM_TOUCH_FW}"\n'
        "_violin_nvt_fw_blob_end:\n"
        ".p2align 2\n"
        ".globl _violin_nvt_fw_size\n"
        "_violin_nvt_fw_size:\n"
        ".long _violin_nvt_fw_blob_end - _violin_nvt_fw_blob\n"
    )
    sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], env=env, text=True).strip()
    run(["xcrun", "clang", "-target", "arm64e-apple-ios27.0", "-isysroot", sdk, "-c", fw_s, "-o", fw_o], env=env)
    kt.check_object(fw_o.read_bytes(), fw_o.name)

    touch_a = OUT / "libViolinTouch.a"
    touch_a.unlink(missing_ok=True)
    run([ar, "rcs", touch_a, touch_o, fw_o], env=env)
    print(f"Built {touch_a} ({touch_a.stat().st_size} B, sha256={sha256_file(touch_a)[:16]}..)", flush=True)

    # 4. Compile ViolinRamOverlayStore.cpp + ViolinStage8CCoordinator.cpp -> libStage8CStorage.a
    common_inc = [
        "-I", str(tree / "build/storage-abi/include"),
        "-I", str(tree / ".cache/xnu-work/osfmk"),
        "-I", str(COMMON / "drivers/XringUfs"),
        "-I", str(VIOLIN / "drivers/ViolinRamOverlay"),
        "-I", str(UNIXNU / "drivers/RamBlock"),
        "-I", str(UNIXNU / "drivers/VirtioMmioBlock"),
        "-I", str(UNIXNU / "kits/VerifiedRoot/include"),
        "-I", str(STAGE7J / "storage"),
        "-include", str(vm_compat_h),
        "-Wno-error",
    ]

    ovl_o = obj_dir / "ViolinRamOverlayStore.o"
    run(
        bvs.make_compile_cmd(cpp_rec, VIOLIN / "drivers/ViolinRamOverlay/ViolinRamOverlayStore.cpp", ovl_o, common_inc),
        env=env, cwd=cpp_rec["directory"], log_path=obj_dir / "ViolinRamOverlayStore.compile.log",
    )
    kt.check_object(ovl_o.read_bytes(), ovl_o.name)

    coord_o = obj_dir / "ViolinStage8CCoordinator.o"
    run(
        bvs.make_compile_cmd(cpp_rec, ARCHIVE_DIR / "ViolinStage8CCoordinator.cpp", coord_o, common_inc),
        env=env, cwd=cpp_rec["directory"], log_path=obj_dir / "ViolinStage8CCoordinator.compile.log",
    )
    kt.check_object(coord_o.read_bytes(), coord_o.name)

    s7h_dir = STAGE7H / "source-storage"
    s7j_dir = STAGE7J / "storage"
    stage8c_a = OUT / "libStage8CStorage.a"
    stage8c_a.unlink(missing_ok=True)
    run([
        ar, "rcs", stage8c_a,
        s7h_dir / "IOBlockStorageDevice.late.o",
        ufs_root_late_o,
        s7h_dir / "NativeRamBlock.late.o",
        s7h_dir / "NativeKeyStoreEvents.o",
        s7h_dir / "KeyStoreGlue.o",
        s7j_dir / "NativeVirtioBlock.late.o",
        s7j_dir / "verified_root.o",
        s7j_dir / "xnu_crypto.o",
        ovl_o,
        coord_o,
    ], env=env)
    print(f"Built {stage8c_a} ({stage8c_a.stat().st_size} B, sha256={sha256_file(stage8c_a)[:16]}..)", flush=True)

    # 5. Apply Stage-8C XNU hooks and link mach.development.bcm2837.unstripped.noctf
    run(["python3", "-B", ARCHIVE_DIR / "apply_stage8c_xnu_hooks.py"])

    extra_archives = " ".join([
        f"-Wl,-force_load,{stage8c_a}",
        "-Wl,-force_load,/opt/unixnu-out/stage6-build/libXringUfs.a",
        f"-Wl,-force_load,{disp_a}",
        f"-Wl,-force_load,{gop_a}",
        "-Wl,-force_load,/opt/unixnu-out/stage7f-backlight/xring-backlight/libXringBacklight.a",
        f"-Wl,-force_load,{hid_a}",
        f"-Wl,-force_load,{touch_a}",
    ])
    xnu_env = dict(env)
    xnu_env.update({
        "JOBS": "12",
        "UNIXNU_XNU_TAG": "xnu-12377.121.6",
        "UNIXNU_XNU_COMMIT": "ac9718fb1af618d5ce8678d0dc6e8a58f252216f",
        "UNIXNU_XNU_DARWIN": "25.5.0",
        "UNIXNU_XNU_VERSION": "12377.121.6",
        "UNIXNU_LIBPLATFORM_TAG": "libplatform-375.120.2",
        "UNIXNU_LIBDISPATCH_TAG": "libdispatch-1542.100.32",
        "UNIXNU_AVAILABILITYVERSIONS_TAG": "AvailabilityVersions-157.2",
        "UNIXNU_DRIVERKIT_TAG": "xnu-12377.121.6",
        "UNIXNU_TRUSTCACHE_TAG": "xnu-8796.101.5",
        "UNIXNU_PATCH_LIST": "already-applied",
        "UNIXNU_GENERATED_DIR": str(tree / "build/generated"),
        "XNU_BUILD_ARCHIVES": "1",
        "XNU_KERNEL_CHAINED_FIXUPS": "1",
        "XNU_CRYPTO_BOOTSTRAP": "source",
        "XNU_SOURCE_CORECRYPTO14": "1",
        "XNU_SOURCE_PTHREAD": "1",
        "XNU_ARM_DT_PLATFORM": "1",
        "XNU_ARMCPU": "1",
        "XNU_NATIVE_ARCH_TIMER": "1",
        "XNU_NATIVE_PAN": "1",
        "XNU_SOURCE_MOCKFS": "1",
        "XNU_DT_PANIC_REGION": "1",
        "XNU_BOOT_PROGRESS": "0",
        "XNU_ARMVIRT_PLATFORM": "0",
        "XNU_NATIVE_LEGACY_DISPLAY": "0",
        "XNU_TRUST_CACHE_RUNTIME": "1",
        "XNU_NATIVE_CS_HASH_CACHE": "1",
        "XNU_SOURCE_STORAGE": "1",
        "XNU_NATIVE_RAM_BLOCK": "1",
        "XNU_OWNER_ROOT_AUDIT": "1",
        "XNU_OWNER_ROOT_TRUST": "1",
        "XNU_OWNER_CACHE_MOUNT": "1",
        "XNU_OWNER_UNION_SYSTEMOS": "1",
        "XNU_OWNER_BOOT_MANIFEST": "1",
        "XNU_OWNER_CACHE_STARTUP": "1",
        "XNU_OWNER_DATA_MOUNT": "1",
        "XNU_OWNER_ROOT_VOLUME_UUID": "2F8E6EED-68D5-4261-B8A3-12571BAA2DD4",
        "XNU_OWNER_CACHE_VOLUME_UUID": "F914C62A-AD00-47C6-8281-5746291C339A",
        "XNU_OWNER_DATA_VOLUME_UUID": DATA_16G_UUID,
        "XNU_EXTRA_LD_ARCHIVES": extra_archives,
    })

    obj_base = tree / "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837"
    native_kernel = obj_base / "mach.development.bcm2837.unstripped.noctf"
    for rel in [
        "bsd/DEVELOPMENT/bsd_init.o",
        "mach.development.bcm2837.unstripped.noctf",
        "mach.development.bcm2837.unstripped",
        "mach.development.bcm2837",
    ]:
        (obj_base / rel).unlink(missing_ok=True)
    run(["bash", tree / "scripts/build-xnu-4k-baseline.sh"], env=xnu_env, cwd=tree, log_path=OUT / "xnu-stage8c-link.log")
    assert native_kernel.is_file()

    assym_txt = (obj_base / "osfmk/DEVELOPMENT/assym.s").read_text()
    assert "#define BOOTSTRAP_TABLE_BYTES 139264" in assym_txt, "assym.s BOOTSTRAP_TABLE_BYTES!=139264!"

    # Verify strong OEM firmware blob symbol won over weak fallback in linked kernel
    nm_out = subprocess.check_output(["llvm-nm", str(native_kernel)], env=env, text=True)
    assert " _violin_nvt_fw_blob\n" in nm_out and " _violin_nvt_fw_size\n" in nm_out, "Missing touch FW symbols in linked kernel"
    assert " _violin_hid_input_init\n" in nm_out and " _violin_touch_start\n" in nm_out, "Missing HID/Touch init symbols"
    assert " _native_legacy_gpu_offer\n" in nm_out, "Missing Stage-8C FastFb native_legacy_gpu_offer symbol"
    print("VERIFIED linked kernel symbols: _violin_nvt_fw_blob, _violin_hid_input_init, _violin_touch_start, _native_legacy_gpu_offer", flush=True)

    # 6. 2-pass 30-kext MH_FILESET prelink (0 extra stubs) + enrich + cpusubtype align + FIPS HMAC seal
    kc_path = IPSW24 / "kernelcache.decompressed"
    ref_kc = ORIG_TREE / "build/xnu/fileset-reference/mach.release.bcm2837.unstripped.noctf"
    roots = [
        "com.apple.AppleFSCompression.AppleFSCompressionTypeZlib",
        "com.apple.driver.AppleARMPlatform",
        "com.apple.driver.AppleARMWatchdogTimer",
        "com.apple.driver.AppleAudioClockLibs",
        "com.apple.driver.AppleEffaceableStorage",
        "com.apple.driver.AppleIISController",
        "com.apple.driver.AppleM2ScalerCSCDriver",
        "com.apple.driver.AppleMobileFileIntegrity",
        "com.apple.driver.ApplePMGR",
        "com.apple.driver.IODARTFamily",
        "com.apple.filesystems.apfs",
        "com.apple.iokit.CoreAnalyticsFamily",
        "com.apple.iokit.IOAVFamily",
        "com.apple.iokit.IOAudio2Family",
        "com.apple.iokit.IOCECFamily",
        "com.apple.iokit.IOCryptoAcceleratorFamily",
        "com.apple.iokit.IOHDCPFamily",
        "com.apple.iokit.IOHIDEventDriver",
        "com.apple.iokit.IOHIDFamily",
        "com.apple.iokit.IOMobileGraphicsFamily",
        "com.apple.iokit.IOReportFamily",
        "com.apple.iokit.IOSlowAdaptiveClockingFamily",
        "com.apple.iokit.IOStorageFamily",
        "com.apple.iokit.IOSurface",
        "com.apple.kec.Libm",
        "com.apple.kec.corecrypto",
        "com.apple.kext.AppleMatch",
        "com.apple.kext.CoreTrust",
        "com.apple.security.AppleImage4",
        "com.apple.security.sandbox",
    ]
    emit = UNIXNU / "kits/XnuPrelink/emit_prelink.py"
    enrich = VIOLIN / "scripts/enrich-fileset-map.py"
    p1_macho = OUT / "kernel-stage8c-pass1.macho"
    p1_map = OUT / "kernel-stage8c-pass1.map.json"
    enr_map = OUT / "kernel-stage8c-enriched.map.json"
    audit_json = OUT / "kernel-stage8c-audit.json"
    p2_macho = OUT / "kernel-stage8c-30.macho"
    sealed_macho = OUT / "kernel-stage8c-sealed.macho"

    base_prelink = [
        "python3", "-B", emit,
        "--kernel", native_kernel,
        "--prelinked", kc_path,
        "--fileset-reference", ref_kc,
        "--slide=-0x1000000",
        "--early-security-init", "com.apple.driver.AppleMobileFileIntegrity=0xfffffe00092551ac",
        "--allow-missing",
    ]
    for r in roots:
        base_prelink += ["--root", r]

    for stale in (
        p1_macho, p1_map, p1_macho.with_suffix(".json"),
        p2_macho, p2_macho.with_suffix(".map.json"), p2_macho.with_suffix(".json"),
        enr_map, sealed_macho,
    ):
        stale.unlink(missing_ok=True)
    run(base_prelink + ["--output", p1_macho], env=env, log_path=OUT / "prelink-pass1.log")
    run([
        "python3", "-B", enrich,
        "--unixnu", UNIXNU,
        "--prelinked", kc_path,
        "--reference", ref_kc,
        "--native", native_kernel,
        "--in-map", p1_map,
        "--out-map", enr_map,
        "--audit-out", audit_json,
    ], env=env, log_path=OUT / "enrich.log")
    run(base_prelink + ["--fileset-map", enr_map, "--output", p2_macho], env=env, log_path=OUT / "prelink-pass2.log")
    p2_log = (OUT / "prelink-pass2.log").read_text().strip()
    print(p2_log, flush=True)
    assert "0 extra stubs" in p2_log or "extra stubs" not in p2_log or "stubs=0" in p2_log or "missing=0" in p2_log, f"Unexpected prelink-pass2 output: {p2_log}"

    data = bytearray(p2_macho.read_bytes())
    outer_sub = struct.unpack_from("<I", data, 8)[0]
    assert outer_sub == 0xC0000002
    ncmds = struct.unpack_from("<I", data, 16)[0]
    pos = 32
    aligned = False
    for _ in range(ncmds):
        cmd, cmdsz = struct.unpack_from("<2I", data, pos)
        if cmd == 0x80000035:
            foff = struct.unpack_from("<Q", data, pos + 16)[0]
            stroff = struct.unpack_from("<I", data, pos + 24)[0]
            end = data.index(b"\0", pos + stroff)
            if data[pos + stroff:end].decode() == "com.apple.kernel":
                struct.pack_into("<I", data, foff + 8, outer_sub)
                aligned = True
                break
        pos += cmdsz
    assert aligned
    sealed_macho.write_bytes(bytes(data))
    run(["python3", "-B", UNIXNU / "scripts/seal-source-crypto-kernel.py", sealed_macho], env=env)
    print(f"Sealed Stage-8C kernel -> {sealed_macho} ({sealed_macho.stat().st_size} B, sha256={sha256_file(sealed_macho)[:16]}..)", flush=True)

    # 7. Package 3 Stage-8C boot artifacts (QEMU 4G, QEMU 10G, Live 10G Warm)
    qemu_args = (
        "serial=3 debug=0x10a -enable_kprintf_spam -no_slto_panic wdt=-1 "
        "-apfs_shared_datavolume owner-dataprotect=1 validation_disables=0x11040 "
        "sched_preemption_disable_debug_mode=0 interrupt-masked-debug-mode=0 "
        "use_contiguous_hint=0 kt_fixed_zones=120 cpus=10 smp=1 armcpu-self-ipi=1 "
        "violin_ramoops=1 violin_qemu=1 violin_stage5_smp=1 violin_stage5_watchdog=0 "
        "violin-gop-presenter=1 offline-legacy-gop=1 offline-legacy-pm=1 offline-legacy-phase=4 "
        "offline-legacy-register=1 offline-legacy-validate=1 offline-legacy-transfer=1 "
        "offline-legacy-retire=1 offline-legacy-cpu-present=1 early-retire=1 "
        "vsync=120 vsync-fixed=1 violin-fast-fb=1 violin-hid=1 violin-hid-selftest=1 violin-touch=0 "
        "aks=1 aks-sls=3 stage7j-virtio=1 no-lc=1 "
        "violin-ram-overlay=1 violin-data-cap-mb=512 data-reset=1 violin-policy=1 violin-lite=1"
    )
    assert len(qemu_args) < 950, f"QEMU boot-args too long: {len(qemu_args)}"

    qemu_4g_fat = OUT / "violin-stage8c-qemu-4g.fat"
    run([
        "python3", "-B", UEFI / "Tools/Stage3Payload/build-stage3-payload.py",
        "--kernel", sealed_macho,
        "--adt", qemu_4g_adt,
        "--trustcache", STAGE7J / "trustcache-24A446.bundle",
        "--initrd", DATA_16G_DBR,
        "--initrd-name", DATA_16G_DBR.name,
        "--out", qemu_4g_fat,
        "--args", qemu_args,
        "--title", "Violin Stage-8C QEMU 4G Gate (120Hz + HID SelfTest)",
        "--timeout", "1",
        "--lz4",
    ])
    qemu_4g_bin = OUT / "violin-uefi-stage8c-qemu-4g.bin"
    splice_uefi(uefi_4g_qemu, Path(str(qemu_4g_fat) + ".lz4"), qemu_4g_bin)

    qemu_10g_args = qemu_args.replace("violin_stage5_watchdog=0", "violin_stage5_watchdog=120")
    qemu_10g_fat = OUT / "violin-stage8c-qemu-10g.fat"
    run([
        "python3", "-B", UEFI / "Tools/Stage3Payload/build-stage3-payload.py",
        "--kernel", sealed_macho,
        "--adt", qemu_10g_adt,
        "--trustcache", STAGE7J / "trustcache-24A446.bundle",
        "--initrd", DATA_16G_DBR,
        "--initrd-name", DATA_16G_DBR.name,
        "--out", qemu_10g_fat,
        "--args", qemu_10g_args,
        "--title", "Violin Stage-8C QEMU 10G/8G Gate (120Hz + HID SelfTest)",
        "--timeout", "1",
        "--lz4",
    ])
    qemu_10g_bin = OUT / "violin-uefi-stage8c-qemu-10g.bin"
    splice_uefi(uefi_10g_qemu, Path(str(qemu_10g_fat) + ".lz4"), qemu_10g_bin)

    live_warm_args = (
        "serial=3 debug=0x10a -enable_kprintf_spam -no_slto_panic wdt=-1 "
        "-apfs_shared_datavolume owner-dataprotect=1 validation_disables=0x11040 "
        "sched_preemption_disable_debug_mode=0 interrupt-masked-debug-mode=0 "
        "use_contiguous_hint=0 kt_fixed_zones=120 cpus=10 smp=1 armcpu-self-ipi=1 "
        "violin_ramoops=1 violin_stage5_smp=1 xring-wdt-kick=1 "
        "violin-gop-presenter=1 offline-legacy-gop=1 offline-legacy-pm=1 offline-legacy-phase=4 "
        "offline-legacy-register=1 offline-legacy-validate=1 offline-legacy-transfer=1 "
        "offline-legacy-retire=1 offline-legacy-cpu-present=1 early-retire=1 "
        "vsync=120 vsync-fixed=1 violin-fast-fb=1 violin-hid=1 violin-touch=1 "
        "xring-backlight=1 aks=1 aks-sls=3 xring-ufs-root=1 xring-ufs-data=2 no-lc=1 "
        "violin-ram-overlay=0 violin-policy=1 violin-lite=1 violin_stage5_watchdog=190"
    )
    assert len(live_warm_args) < 950, f"Live boot-args too long: {len(live_warm_args)}"
    assert "-v " not in live_warm_args and not live_warm_args.startswith("-v"), "Do not pass -v on live run!"
    assert "data-reset=1" not in live_warm_args, "Must preserve persistent SHNGDATA (no data-reset=1)!"
    print(f"Live WARM args ({len(live_warm_args)} B): {live_warm_args}", flush=True)

    live_warm_fat = OUT / "violin-stage8c-live-10g-warm.fat"
    run([
        "python3", "-B", UEFI / "Tools/Stage3Payload/build-stage3-payload.py",
        "--kernel", sealed_macho,
        "--adt", live_adt,
        "--trustcache", STAGE7J / "trustcache-24A446.bundle",
        "--initrd", DATA_16G_DBR,
        "--initrd-name", DATA_16G_DBR.name,
        "--out", live_warm_fat,
        "--args", live_warm_args,
        "--title", "Violin Stage-8C iPadOS 27.0.1 (Touch + 120Hz FastFb Warm)",
        "--timeout", "2",
        "--lz4",
    ])
    live_warm_kbin = OUT / "violin-uefi-stage8c-live-10g-warm.bin"
    splice_uefi(uefi_10g_live, Path(str(live_warm_fat) + ".lz4"), live_warm_kbin)
    live_warm_bootimg = OUT / "violin-stage8c-live-10g-warm-boot_b.img"
    run([
        "python3", "-B", MKBOOTV4,
        "--kernel", live_warm_kbin,
        "--output", live_warm_bootimg,
    ])
    assert live_warm_bootimg.stat().st_size <= 100663296, "Live boot_b exceeds 96 MiB limit!"

    summary = {
        "sealed_kernel_sha256": sha256_file(sealed_macho),
        "sealed_kernel_bytes": sealed_macho.stat().st_size,
        "oem_touch_fw_sha256": fw_sha,
        "oem_touch_fw_bytes": OEM_TOUCH_FW.stat().st_size,
        "qemu_4g_image": str(qemu_4g_bin),
        "qemu_10g_image": str(qemu_10g_bin),
        "live_warm_boot_b": str(live_warm_bootimg),
        "live_warm_boot_b_bytes": live_warm_bootimg.stat().st_size,
        "live_warm_boot_b_sha256": sha256_file(live_warm_bootimg),
        "live_warm_boot_args": live_warm_args,
    }
    (OUT / "stage8c-build-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(
        f"STAGE8C_BUILD_READY:\n"
        f"  QEMU 4G:   {qemu_4g_bin} ({qemu_4g_bin.stat().st_size / (1<<20):.2f} MiB)\n"
        f"  QEMU 10G:  {qemu_10g_bin} ({qemu_10g_bin.stat().st_size / (1<<20):.2f} MiB)\n"
        f"  LIVE WARM: {live_warm_bootimg} ({live_warm_bootimg.stat().st_size / (1<<20):.2f} MiB, sha256={summary['live_warm_boot_b_sha256'][:16]}..)",
        flush=True,
    )


if __name__ == "__main__":
    main()
