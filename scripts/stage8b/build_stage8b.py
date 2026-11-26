#!/usr/bin/env python3
"""
Build Stage-8B Route A: 10 GiB Bank 1 UEFI (8 GiB XNU owned_memory_size) +
kern.maxvnodes=32768 + Persistent UFS 4.1 SHNGDATA Backing Store
for Xiaomi Pad 7S Pro (violin / O81A / XRING O1 / ipados-27.0.1-24A446):

  1. Runs host ASan/UBSan TDD for ViolinRamOverlay AND XringUfsRoot
     (test_shng_root_core 6/6 + ShngDataCore.h strict C11 + test_shng_data_core 5/5).
  2. Rebuilds & PAC-audits:
     - XringUfsRoot.late.o (190/190 PAC slots, fenced SHNGDATA + strictly RO SHNGROOT)
     - libNativeLegacyDisplay.late.a (379/379 PAC slots, DEFAULT_SURFACE=1)
     - libViolinGopPresenter.a
  3. Compiles ViolinRamOverlayStore.cpp (UFS/DRAM dispatch) +
     ViolinStage8BCoordinator.cpp -> libStage8BStorage.a.
  4. Applies Stage-8B isolated xnu-work hooks (BOOTSTRAP_TABLE_SIZE=34,
     warm-resume-safe ViolinBootPolicy, pre-reboot sync_internal + doSynchronizeCache,
     rich [VIOLIN_HB]), rebuilds genassym/assym.s/start.o/pmap.o/arm_vm_init.o/BSD,
     and asserts BOOTSTRAP_TABLE_BYTES == 139264 in regenerated assym.s.
  5. Links, runs 2-pass 30-kext MH_FILESET prelink (0 extra stubs), aligns cpusubtype,
     and FIPS HMAC seals -> kernel-stage8b-sealed.macho.
  6. Generates 3 ADTs (all with /defaults kern.maxvnodes=32768 + Stage-8A display identity):
     - QEMU 4 GiB (dram=4 GiB, owned=3.25 GiB)
     - QEMU 10 GiB (dram=10 GiB, owned=8 GiB exact)
     - Live 10 GiB (dram=10 GiB, owned=8 GiB exact)
  7. Builds 4 bootable artifacts:
     - violin-uefi-stage8b-qemu-4g.bin  (QEMU -smp 10 -m 8G)
     - violin-uefi-stage8b-qemu-10g.bin (QEMU -smp 10 -m 13G)
     - violin-stage8b-live-10g-cold-boot_b.img (Run 1: xring-ufs-data=2 data-reset=1 wd=240)
     - violin-stage8b-live-10g-warm-boot_b.img (Run 2: xring-ufs-data=2 [NO reset] wd=150)
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tomllib

ARCHIVE_DIR = Path(__file__).resolve().parent
VIOLIN = Path(os.environ.get("UNIXNU_VIOLIN_DIR", str(ARCHIVE_DIR.parents[1])))
SOURCE_ROOT = VIOLIN.parent
UNIXNU = Path(os.environ.get("UNIXNU_DIR", str(SOURCE_ROOT / "UniXNU")))
COMMON = Path(os.environ.get("UNIXNU_COMMON_DIR", str(SOURCE_ROOT / "UniXNU-xring-o1-common")))
UEFI = Path(os.environ.get("UNIXNU_UEFI_DIR", str(SOURCE_ROOT / "uefi-violin")))
MKBOOTV4 = ARCHIVE_DIR.parent / "stage8a" / "mkbootv4.py"
UNIQUE_CHIP_ID = os.environ.get("VIOLIN_UNIQUE_CHIP_ID", "0000000000000000")

ORIG_TREE = Path("/opt/unixnu-out/violin/ipados-27.0.1-24A446/violin/tree")
STAGE7H = Path("/opt/unixnu-out/stage7h-apfs")
STAGE7J = Path("/opt/unixnu-out/stage7j-qemu-launchd")
STAGE7K = Path("/opt/unixnu-out/stage7k-launchd-4g")
IPSW24 = Path("/opt/unixnu-out/ipsw/24A446")
ASSETS24 = Path("/opt/unixnu-out/macos26-assets-24A446")
OUT = Path("/opt/unixnu-out/stage8b-mem10g-shngdata")

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
            tail = Path(log_path).read_text(errors="replace")[-3500:]
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


def deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def inject_stage8b_adt_identity(merged: dict) -> dict:
    adt = merged.setdefault("adt", {})
    # Stage-8B: override CONFIG_VNODES=1024 via PE_get_default("kern.maxvnodes") -> /defaults
    defaults_u32 = adt.setdefault("defaults", {}).setdefault("u32", {})
    defaults_u32["kern.maxvnodes"] = 32768

    chosen_u32 = adt.setdefault("chosen", {}).setdefault("u32", {})
    chosen_u32["display-scale"] = 2
    chosen_u32["display-rotation"] = 0
    adt["product"] = {
        "string": {
            "product-name": "iPad Pro (13-inch) (M4)",
            "product-description": "iPad Pro (13-inch) (M4)",
            "artwork-device-idiom": "pad",
            "artwork-display-gamut": "sRGB",
            "compatible-device-fallback": "iPad17,3",
        },
        "u32": {
            "artwork-device-subtype": 2732,
            "artwork-scale-factor": 2,
            "thin-bezel": 1,
        },
    }
    adt["buttons"] = {
        "string": {
            "compatible": "buttons",
            "device_type": "buttons",
        },
        "strings": {
            "button-names": ["hold", "voldown", "volup"],
        },
        "u32": {
            "home-button-type": 2,
        },
    }
    return merged


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
    uefi_4g_qemu = OUT / "violin-uefi-4g-qemu.bin"
    uefi_10g_qemu = OUT / "violin-uefi-10g-qemu.bin"
    uefi_10g_live = OUT / "violin-uefi-10g-live.bin"
    for p in (uefi_4g_qemu, uefi_10g_qemu, uefi_10g_live):
        assert p.is_file(), f"Missing Stage-8B UEFI base binary: {p}"

    OUT.mkdir(parents=True, exist_ok=True)
    obj_dir = OUT / "obj"
    obj_dir.mkdir(parents=True, exist_ok=True)
    tree = STAGE7J / "tree"
    env = linux_env(tree)

    # 1. Host ASan/UBSan TDD for ViolinRamOverlay
    host_env = dict(os.environ)
    host_env["PATH"] = "/usr/bin:/bin"
    tdd_bin = OUT / "test_ram_overlay"
    run([
        "g++", "-std=c++17", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined",
        f"-I{VIOLIN / 'drivers/ViolinRamOverlay'}",
        f"-I{UNIXNU / 'drivers/RamBlock'}",
        VIOLIN / "drivers/ViolinRamOverlay/Test/test_ram_overlay.cpp",
        "-o", tdd_bin,
    ], env=host_env)
    run([tdd_bin], env=host_env)

    # 2. Rebuild & PAC-audit XringUfsRoot.late.o (190/190 + ShngRootCore + ShngDataCore TDD)
    #    + libNativeLegacyDisplay.late.a (379/379) + libViolinGopPresenter.a
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

    # 3. Compile ViolinRamOverlayStore.cpp + ViolinStage8BCoordinator.cpp -> libStage8BStorage.a
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

    coord_o = obj_dir / "ViolinStage8BCoordinator.o"
    run(
        bvs.make_compile_cmd(cpp_rec, ARCHIVE_DIR / "ViolinStage8BCoordinator.cpp", coord_o, common_inc),
        env=env, cwd=cpp_rec["directory"], log_path=obj_dir / "ViolinStage8BCoordinator.compile.log",
    )
    kt.check_object(coord_o.read_bytes(), coord_o.name)

    s7h_dir = STAGE7H / "source-storage"
    s7j_dir = STAGE7J / "storage"
    ar = bvs.find_tool(["llvm-ar", "llvm-ar-21", "llvm-ar-20", "ar"])
    stage8b_a = OUT / "libStage8BStorage.a"
    stage8b_a.unlink(missing_ok=True)
    run([
        ar, "rcs", stage8b_a,
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
    print(f"Built {stage8b_a} ({stage8b_a.stat().st_size} B, sha256={sha256_file(stage8b_a)[:16]}..)", flush=True)

    # 4. Apply isolated Stage-8B XNU hooks and force clean recompile of genassym/start/pmap/BSD
    run(["python3", "-B", ARCHIVE_DIR / "apply_stage8b_xnu_hooks.py"])

    extra_archives = " ".join([
        f"-Wl,-force_load,{stage8b_a}",
        "-Wl,-force_load,/opt/unixnu-out/stage6-build/libXringUfs.a",
        f"-Wl,-force_load,{disp_a}",
        f"-Wl,-force_load,{gop_a}",
        "-Wl,-force_load,/opt/unixnu-out/stage7f-backlight/xring-backlight/libXringBacklight.a",
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
        "osfmk/DEVELOPMENT/genassym.o",
        "osfmk/DEVELOPMENT/assym.s",
        "osfmk/DEVELOPMENT/start.o",
        "osfmk/DEVELOPMENT/arm_vm_init.o",
        "osfmk/DEVELOPMENT/pmap.o",
        "osfmk/DEVELOPMENT/sleh.o",
        "osfmk/DEVELOPMENT/task.o",
        "bsd/DEVELOPMENT/kern_exec.o",
        "bsd/DEVELOPMENT/bsd_init.o",
        "bsd/DEVELOPMENT/kern_exit.o",
        "bsd/DEVELOPMENT/kern_sig.o",
        "bsd/DEVELOPMENT/kern_proc.o",
        "bsd/DEVELOPMENT/mach_loader.o",
        "bsd/DEVELOPMENT/kpi_vfs.o",
        "security/DEVELOPMENT/mac_process.o",
        "mach.development.bcm2837.unstripped.noctf",
        "mach.development.bcm2837.unstripped",
        "mach.development.bcm2837",
    ]:
        (obj_base / rel).unlink(missing_ok=True)
    run(["bash", tree / "scripts/build-xnu-4k-baseline.sh"], env=xnu_env, cwd=tree, log_path=OUT / "xnu-stage8b-link.log")
    assert native_kernel.is_file()

    # Critical assertion: verify assym.s regenerated BOOTSTRAP_TABLE_BYTES = 34 * 4096 = 139264
    assym_txt = (obj_base / "osfmk/DEVELOPMENT/assym.s").read_text()
    assert "#define BOOTSTRAP_TABLE_BYTES 139264" in assym_txt, "assym.s did NOT regenerate BOOTSTRAP_TABLE_BYTES=139264!"
    print("VERIFIED assym.s: #define BOOTSTRAP_TABLE_BYTES 139264 (34 pages)", flush=True)

    # 5. 2-pass 30-kext MH_FILESET prelink (0 extra stubs) + enrich + cpusubtype align + FIPS HMAC seal
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
    p1_macho = OUT / "kernel-stage8b-pass1.macho"
    p1_map = OUT / "kernel-stage8b-pass1.map.json"
    enr_map = OUT / "kernel-stage8b-enriched.map.json"
    audit_json = OUT / "kernel-stage8b-audit.json"
    p2_macho = OUT / "kernel-stage8b-30.macho"
    sealed_macho = OUT / "kernel-stage8b-sealed.macho"

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
    print(f"Sealed Stage-8B kernel -> {sealed_macho} ({sealed_macho.stat().st_size} B, sha256={sha256_file(sealed_macho)[:16]}..)", flush=True)

    # 6. Generate 3 ADTs (QEMU 4G, QEMU 10G/8G-owned, Live 10G/8G-owned)
    sys.path.insert(0, str(UNIXNU / "scripts"))
    from unixnu import devicetree as dtmod

    os_prof = tomllib.loads((UNIXNU / "profiles/os/ipados-27.0.1-24A446/profile.toml").read_text())
    board_cfg = tomllib.loads((VIOLIN / "board.toml").read_text())

    def check_adt_tokens(blob: bytes, label: str):
        for tok in (
            b"PackedRAMDisk\0",
            b"TrustCache\0",
            b"kern.maxvnodes\0",
            b"display-scale\0",
            b"display-rotation\0",
            b"artwork-device-idiom\0",
            b"home-button-type\0",
            b"button-names\0",
        ):
            assert tok in blob, f"{label}: missing expected ADT token {tok!r}"
        assert b"ephemeral-storage\0" not in blob, f"{label}: ephemeral-storage must be omitted!"

    # 6a. QEMU 4 GiB ADT
    qemu_4g_dtb = STAGE7K / "violin-stage7k-qemu-4g.dtb"
    assert qemu_4g_dtb.is_file()
    q4_merged = inject_stage8b_adt_identity(deep_merge(os_prof, board_cfg))
    q4_merged.setdefault("payload", {}).setdefault("adt", {})
    q4_merged["payload"]["dram_size"] = "0x100000000"
    q4_merged["payload"]["adt"]["owned_memory_size"] = "0xD0000000"
    q4_merged["payload"]["adt"]["psci_method"] = "hvc"
    q4_merged["payload"]["adt"]["packed_data_ramdisk"] = True
    q4_merged["payload"]["adt"]["persistent_data"] = True
    q4_merged["payload"]["adt"]["root_match_volume_uuid"] = "2F8E6EED-68D5-4261-B8A3-12571BAA2DD4"
    qemu_4g_adt = OUT / "violin-stage8b-qemu-4g.adt"
    q4_bytes = dtmod.generate(qemu_4g_dtb, q4_merged, unique_chip_id=UNIQUE_CHIP_ID, data=True, trust=True)
    check_adt_tokens(q4_bytes, "qemu-4g")
    qemu_4g_adt.write_bytes(q4_bytes)

    # 6b. QEMU 10 GiB (8 GiB owned_memory_size) DTS/DTB/ADT
    qemu_4g_dts_txt = subprocess.check_output(["dtc", "-I", "dtb", "-O", "dts", str(qemu_4g_dtb)], text=True)
    qemu_10g_dts_txt, nrep = re.subn(
        r"(memory@100000000\s*\{[^}]*reg\s*=\s*<)0x0?1\s+0x00\s+0x0?1\s+0x00(>;)",
        r"\g<1>0x01 0x00 0x02 0x80000000\g<2>",
        qemu_4g_dts_txt,
        count=1,
    )
    assert nrep == 1, "Failed to expand QEMU DTS memory@100000000 to 10 GiB"
    qemu_10g_dts = OUT / "violin-stage8b-qemu-10g.dts"
    qemu_10g_dtb = OUT / "violin-stage8b-qemu-10g.dtb"
    qemu_10g_adt = OUT / "violin-stage8b-qemu-10g.adt"
    qemu_10g_dts.write_text(qemu_10g_dts_txt)
    run(["dtc", "-I", "dts", "-O", "dtb", "-o", str(qemu_10g_dtb), str(qemu_10g_dts)])

    q10_merged = inject_stage8b_adt_identity(deep_merge(os_prof, board_cfg))
    q10_merged.setdefault("payload", {}).setdefault("adt", {})
    q10_merged["payload"]["dram_size"] = "0x280000000"
    q10_merged["payload"]["adt"]["owned_memory_size"] = "0x200000000"
    q10_merged["payload"]["adt"]["psci_method"] = "hvc"
    q10_merged["payload"]["adt"]["packed_data_ramdisk"] = True
    q10_merged["payload"]["adt"]["persistent_data"] = True
    q10_merged["payload"]["adt"]["root_match_volume_uuid"] = "2F8E6EED-68D5-4261-B8A3-12571BAA2DD4"
    q10_bytes = dtmod.generate(qemu_10g_dtb, q10_merged, unique_chip_id=UNIQUE_CHIP_ID, data=True, trust=True)
    check_adt_tokens(q10_bytes, "qemu-10g")
    qemu_10g_adt.write_bytes(q10_bytes)

    # 6c. Live 10 GiB (8 GiB owned_memory_size) DTS/DTB/ADT
    live_dts_txt = (VIOLIN / "dts/violin.dts").read_text().replace(
        "reg = <0x1 0x0 0x0 0x80000000>;",
        "reg = <0x1 0x0 0x2 0x80000000>;",
    )
    assert "reg = <0x1 0x0 0x2 0x80000000>;" in live_dts_txt
    live_dts = OUT / "violin-stage8b-live-10g.dts"
    live_dtb = OUT / "violin-stage8b-live-10g.dtb"
    live_adt = OUT / "violin-stage8b-live-10g.adt"
    live_dts.write_text(live_dts_txt)
    run(["dtc", "-I", "dts", "-O", "dtb", "-i", str(COMMON / "dts"), "-o", str(live_dtb), str(live_dts)])

    live_merged = inject_stage8b_adt_identity(deep_merge(os_prof, board_cfg))
    live_merged.setdefault("payload", {}).setdefault("adt", {})
    live_merged["payload"]["dram_size"] = "0x280000000"
    live_merged["payload"]["adt"]["owned_memory_size"] = "0x200000000"
    live_merged["payload"]["adt"]["psci_method"] = "smc"
    live_merged["payload"]["adt"]["packed_data_ramdisk"] = True
    live_merged["payload"]["adt"]["persistent_data"] = True
    live_merged["payload"]["adt"]["root_match_volume_uuid"] = "2F8E6EED-68D5-4261-B8A3-12571BAA2DD4"
    live_bytes = dtmod.generate(live_dtb, live_merged, unique_chip_id=UNIQUE_CHIP_ID, data=True, trust=True)
    check_adt_tokens(live_bytes, "live-10g")
    live_adt.write_bytes(live_bytes)
    print(f"Generated ADTs: qemu4g={len(q4_bytes)}B, qemu10g={len(q10_bytes)}B, live10g={len(live_bytes)}B", flush=True)

    # 7. Package 4 boot artifacts
    qemu_args = (
        "serial=3 debug=0x10a -enable_kprintf_spam -no_slto_panic wdt=-1 "
        "-apfs_shared_datavolume owner-dataprotect=1 validation_disables=0x11040 "
        "sched_preemption_disable_debug_mode=0 interrupt-masked-debug-mode=0 "
        "use_contiguous_hint=0 kt_fixed_zones=120 cpus=10 smp=1 armcpu-self-ipi=1 "
        "violin_ramoops=1 violin_qemu=1 violin_stage5_smp=1 violin_stage5_watchdog=0 "
        "violin-gop-presenter=1 offline-legacy-gop=1 offline-legacy-pm=1 offline-legacy-phase=4 "
        "offline-legacy-register=1 offline-legacy-validate=1 offline-legacy-transfer=1 "
        "offline-legacy-retire=1 offline-legacy-cpu-present=1 vsync=60 vsync-fixed=1 "
        "aks=1 aks-sls=3 stage7j-virtio=1 no-lc=1 "
        "violin-ram-overlay=1 violin-data-cap-mb=512 data-reset=1 violin-policy=1 violin-lite=1"
    )

    qemu_4g_fat = OUT / "violin-stage8b-qemu-4g.fat"
    run([
        "python3", "-B", UEFI / "Tools/Stage3Payload/build-stage3-payload.py",
        "--kernel", sealed_macho,
        "--adt", qemu_4g_adt,
        "--trustcache", STAGE7J / "trustcache-24A446.bundle",
        "--initrd", DATA_16G_DBR,
        "--initrd-name", DATA_16G_DBR.name,
        "--out", qemu_4g_fat,
        "--args", qemu_args,
        "--title", "Violin Stage-8B QEMU 4G Gate (maxvnodes=32768)",
        "--timeout", "1",
        "--lz4",
    ])
    qemu_4g_bin = OUT / "violin-uefi-stage8b-qemu-4g.bin"
    splice_uefi(uefi_4g_qemu, Path(str(qemu_4g_fat) + ".lz4"), qemu_4g_bin)

    qemu_10g_args = qemu_args.replace("violin_stage5_watchdog=0", "violin_stage5_watchdog=120")
    qemu_10g_fat = OUT / "violin-stage8b-qemu-10g.fat"
    run([
        "python3", "-B", UEFI / "Tools/Stage3Payload/build-stage3-payload.py",
        "--kernel", sealed_macho,
        "--adt", qemu_10g_adt,
        "--trustcache", STAGE7J / "trustcache-24A446.bundle",
        "--initrd", DATA_16G_DBR,
        "--initrd-name", DATA_16G_DBR.name,
        "--out", qemu_10g_fat,
        "--args", qemu_10g_args,
        "--title", "Violin Stage-8B QEMU 10G/8G Gate (maxvnodes=32768 + 8GiB Window)",
        "--timeout", "1",
        "--lz4",
    ])
    qemu_10g_bin = OUT / "violin-uefi-stage8b-qemu-10g.bin"
    splice_uefi(uefi_10g_qemu, Path(str(qemu_10g_fat) + ".lz4"), qemu_10g_bin)

    live_common = (
        "serial=3 debug=0x10a -enable_kprintf_spam -no_slto_panic wdt=-1 "
        "-apfs_shared_datavolume owner-dataprotect=1 validation_disables=0x11040 "
        "sched_preemption_disable_debug_mode=0 interrupt-masked-debug-mode=0 "
        "use_contiguous_hint=0 kt_fixed_zones=120 cpus=10 smp=1 armcpu-self-ipi=1 "
        "violin_ramoops=1 violin_stage5_smp=1 xring-wdt-kick=1 "
        "violin-gop-presenter=1 offline-legacy-gop=1 offline-legacy-pm=1 offline-legacy-phase=4 "
        "offline-legacy-register=1 offline-legacy-validate=1 offline-legacy-transfer=1 "
        "offline-legacy-retire=1 offline-legacy-cpu-present=1 vsync=60 vsync-fixed=1 "
        "xring-backlight=1 aks=1 aks-sls=3 xring-ufs-root=1 xring-ufs-data=2 no-lc=1 "
        "violin-ram-overlay=0 violin-policy=1 violin-lite=1"
    )
    live_cold_args = live_common + " data-reset=1 violin_stage5_watchdog=240"
    live_warm_args = live_common + " violin_stage5_watchdog=150"
    for label, args in (("cold", live_cold_args), ("warm", live_warm_args)):
        assert len(args) < 950, f"{label} boot-args too long: {len(args)}"
        assert "-v " not in args and not args.startswith("-v"), f"Do not pass -v on live {label} run!"
    print(f"Live COLD args ({len(live_cold_args)} B): {live_cold_args}", flush=True)
    print(f"Live WARM args ({len(live_warm_args)} B): {live_warm_args}", flush=True)

    live_cold_fat = OUT / "violin-stage8b-live-10g-cold.fat"
    run([
        "python3", "-B", UEFI / "Tools/Stage3Payload/build-stage3-payload.py",
        "--kernel", sealed_macho,
        "--adt", live_adt,
        "--trustcache", STAGE7J / "trustcache-24A446.bundle",
        "--initrd", DATA_16G_DBR,
        "--initrd-name", DATA_16G_DBR.name,
        "--out", live_cold_fat,
        "--args", live_cold_args,
        "--title", "Violin Stage-8B iPadOS 27.0.1 (8G Window + SHNGDATA Cold Fresh)",
        "--timeout", "2",
        "--lz4",
    ])
    live_cold_kbin = OUT / "violin-uefi-stage8b-live-10g-cold.bin"
    splice_uefi(uefi_10g_live, Path(str(live_cold_fat) + ".lz4"), live_cold_kbin)
    live_cold_bootimg = OUT / "violin-stage8b-live-10g-cold-boot_b.img"
    run([
        "python3", "-B", MKBOOTV4,
        "--kernel", live_cold_kbin,
        "--output", live_cold_bootimg,
    ])
    assert live_cold_bootimg.stat().st_size <= 100663296, "Cold boot_b exceeds 96 MiB limit!"

    live_warm_fat = OUT / "violin-stage8b-live-10g-warm.fat"
    run([
        "python3", "-B", UEFI / "Tools/Stage3Payload/build-stage3-payload.py",
        "--kernel", sealed_macho,
        "--adt", live_adt,
        "--trustcache", STAGE7J / "trustcache-24A446.bundle",
        "--initrd", DATA_16G_DBR,
        "--initrd-name", DATA_16G_DBR.name,
        "--out", live_warm_fat,
        "--args", live_warm_args,
        "--title", "Violin Stage-8B iPadOS 27.0.1 (8G Window + SHNGDATA Warm Resume)",
        "--timeout", "2",
        "--lz4",
    ])
    live_warm_kbin = OUT / "violin-uefi-stage8b-live-10g-warm.bin"
    splice_uefi(uefi_10g_live, Path(str(live_warm_fat) + ".lz4"), live_warm_kbin)
    live_warm_bootimg = OUT / "violin-stage8b-live-10g-warm-boot_b.img"
    run([
        "python3", "-B", MKBOOTV4,
        "--kernel", live_warm_kbin,
        "--output", live_warm_bootimg,
    ])
    assert live_warm_bootimg.stat().st_size <= 100663296, "Warm boot_b exceeds 96 MiB limit!"

    summary = {
        "sealed_kernel_sha256": sha256_file(sealed_macho),
        "sealed_kernel_bytes": sealed_macho.stat().st_size,
        "live_adt_sha256": sha256_file(live_adt),
        "qemu_4g_image": str(qemu_4g_bin),
        "qemu_10g_image": str(qemu_10g_bin),
        "live_cold_boot_b": str(live_cold_bootimg),
        "live_cold_boot_b_bytes": live_cold_bootimg.stat().st_size,
        "live_cold_boot_b_sha256": sha256_file(live_cold_bootimg),
        "live_cold_boot_args": live_cold_args,
        "live_warm_boot_b": str(live_warm_bootimg),
        "live_warm_boot_b_bytes": live_warm_bootimg.stat().st_size,
        "live_warm_boot_b_sha256": sha256_file(live_warm_bootimg),
        "live_warm_boot_args": live_warm_args,
        "data_seed": DATA_16G_DBR.name,
        "data_uuid": DATA_16G_UUID,
    }
    (OUT / "stage8b-build-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(
        f"STAGE8B_BUILD_READY:\n"
        f"  QEMU 4G:   {qemu_4g_bin} ({qemu_4g_bin.stat().st_size / (1<<20):.2f} MiB)\n"
        f"  QEMU 10G:  {qemu_10g_bin} ({qemu_10g_bin.stat().st_size / (1<<20):.2f} MiB)\n"
        f"  LIVE COLD: {live_cold_bootimg} ({live_cold_bootimg.stat().st_size / (1<<20):.2f} MiB, sha256={summary['live_cold_boot_b_sha256'][:16]}..)\n"
        f"  LIVE WARM: {live_warm_bootimg} ({live_warm_bootimg.stat().st_size / (1<<20):.2f} MiB, sha256={summary['live_warm_boot_b_sha256'][:16]}..)",
        flush=True,
    )


if __name__ == "__main__":
    main()
