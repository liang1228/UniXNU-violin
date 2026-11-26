#!/usr/bin/env python3
"""
Build & audit XringUfsRoot (Dual-Boot D1 SHNGROOT v2 + VerifiedRoot IOBlockStorageDevice):
  1. Runs host TDD test_shng_root_core.c under GCC ASan/UBSan + -Werror.
  2. Cross-compiles XringUfsRoot.cpp for arm64e-apple-ios27.0 with -Wall -Wextra -Werror.
  3. Verifies kernel_target.check_object() and 190/190 arm64e PAC vtable match vs 24A446.
  4. Strips __DATA,__mod_init_func & globalizes __GLOBAL__sub_I_XringUfsRoot.cpp -> XringUfsRoot.late.o.
"""
import importlib.util
import json
import os
import subprocess
from pathlib import Path

VIOLIN = Path(os.environ.get("UNIXNU_VIOLIN_DIR", str(Path(__file__).resolve().parents[1])))
SOURCE_ROOT = VIOLIN.parent
UNIXNU = Path(os.environ.get("UNIXNU_DIR", str(SOURCE_ROOT / "UniXNU")))
COMMON = Path(os.environ.get("UNIXNU_COMMON_DIR", str(SOURCE_ROOT / "UniXNU-xring-o1-common")))
STAGE7J = Path("/opt/unixnu-out/stage7j-qemu-launchd")
STAGE7H = Path("/opt/unixnu-out/stage7h-apfs")
IPSW24 = Path("/opt/unixnu-out/ipsw/24A446")
OUT = Path("/opt/unixnu-out/stage7n-dualboot-d1/obj")


def main():
    OUT.mkdir(parents=True, exist_ok=True)

    # 1. Host ASan/UBSan TDD (strict GNU PATH)
    host_env = dict(os.environ)
    host_env["PATH"] = "/usr/bin:/bin"
    host_bin = OUT / "test_shng_root_core"
    subprocess.run([
        "gcc", "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-O1", "-g",
        str(COMMON / "drivers/XringUfs/test_shng_root_core.c"),
        "-o", str(host_bin),
    ], env=host_env, check=True)
    subprocess.run([str(host_bin)], env=host_env, check=True)

    # 1b. Strict C11 syntax check on ShngDataCore.h + C++17 ASan/UBSan PersistOverlay integration TDD
    subprocess.run([
        "gcc", "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-x", "c", "-fsyntax-only",
        "-I", str(COMMON / "drivers/XringUfs"),
        str(COMMON / "drivers/XringUfs/ShngDataCore.h"),
    ], env=host_env, check=True)
    data_bin = OUT / "test_shng_data_core"
    subprocess.run([
        "g++", "-x", "c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-O1", "-g",
        "-I", str(COMMON / "drivers/XringUfs"),
        "-I", str(UNIXNU / "drivers/RamBlock"),
        str(COMMON / "drivers/XringUfs/test_shng_data_core.c"),
        "-o", str(data_bin),
    ], env=host_env, check=True)
    subprocess.run([str(data_bin)], env=host_env, check=True)

    # 2. Load PAC & Mach-O auditors
    spec = importlib.util.spec_from_file_location("bvs", VIOLIN / "scripts/build-violin-source-storage.py")
    bvs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bvs)

    os.environ["UNIXNU_XNU_ARCH"] = "arm64e"
    os.environ["UNIXNU_IOS_VERSION"] = "27.0.1"
    kt = bvs.load_module("kernel_target", UNIXNU / "scripts/kernel_target.py")
    assert kt.ARCH == "arm64e"

    tree = STAGE7J / "tree"
    toolchain = Path("/opt/unixnu-out/toolchain-arm64e")
    clt = toolchain / "CommandLineTools/usr"
    xctc = toolchain / "XcodeDefault.xctoolchain/usr"
    fakeroot = tree / ".cache/fakeroot"
    env = dict(os.environ)
    env.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "LC_ALL": "C",
        "ZERO_AR_DATE": "1",
        "UNIXNU_TOOLCHAIN": str(toolchain),
        "CLT_PREFIX": str(clt),
        "XCTOOLCHAIN_PREFIX": str(xctc),
        "UNIXNU_SDKROOT": str(fakeroot),
        "UNIXNU_SDK_VERSION": "27.0",
        "UNIXNU_IOS_VERSION": "27.0",
        "UNIXNU_XNU_ARCH": "arm64e",
        "UNIXNU_XNU_TARGET": "ios",
        "CROSS_CLANG": str(toolchain / "llvm/bin/clang"),
        "DARWIN_TRIPLE": "arm64e-apple-ios27.0",
        "PATH": f"{clt / 'bin'}:{toolchain / 'bin'}:{tree / 'scripts/linux'}:/opt/unixnu-linux/bin:{os.environ.get('PATH', '')}",
    })

    cpp_rec = json.loads(
        (tree / "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json")
        .read_text().strip().rstrip(",")
    )
    vm_compat_h = STAGE7J / "storage/stage7j_xnu12377_vm_compat.h"
    raw_o = OUT / "XringUfsRoot.o"
    late_o = OUT / "XringUfsRoot.late.o"

    cmd = bvs.make_compile_cmd(
        cpp_rec,
        COMMON / "drivers/XringUfs/XringUfsRoot.cpp",
        raw_o,
        [
            "-I", str(tree / "build/storage-abi/include"),
            "-I", str(tree / ".cache/xnu-work/osfmk"),
            "-I", str(COMMON / "drivers/XringUfs"),
            "-I", str(UNIXNU / "kits/VerifiedRoot/include"),
            "-include", str(vm_compat_h),
            "-Wall", "-Wextra", "-Werror",
            "-Wno-missing-designated-field-initializers",
            "-Wno-unused-parameter",
            "-Wno-c99-designator",
            "-Wno-reorder-init-list",
            "-Wno-deprecated-enum-enum-conversion",
        ],
    )
    subprocess.run(cmd, env=env, cwd=cpp_rec["directory"], check=True)
    kt.check_object(raw_o.read_bytes(), raw_o.name)

    s7h_dir = STAGE7H / "source-storage"
    bsd_vt = bvs.extract_obj_vtable_divs((s7h_dir / "IOBlockStorageDevice.o").read_bytes(), "__ZTV20IOBlockStorageDevice")
    ufs_vt = bvs.extract_obj_vtable_divs(raw_o.read_bytes(), "__ZTV18XringUfsRootWindow")
    bsd_divs = [d for _, _, d in bsd_vt]
    ufs_divs = [d for _, _, d in ufs_vt]
    assert len(bsd_divs) == 190 and len(ufs_divs) == 190, f"len bsd={len(bsd_divs)} ufs={len(ufs_divs)}"
    diffs = [(s, bsd_vt[s][1], ufs_vt[s][1], hex(bsd_divs[s]), hex(ufs_divs[s]))
             for s in range(190) if bsd_divs[s] != ufs_divs[s]]
    assert not diffs, f"PAC diffs: {diffs[:8]}"
    kc_audit = bvs.find_24a446_ioblockstoragedevice_vtable(
        (IPSW24 / "kernelcache.decompressed").read_bytes(), UNIXNU, ufs_divs
    )

    objcopy = bvs.find_tool(["llvm-objcopy", "llvm-objcopy-21", "llvm-objcopy-20"])
    subprocess.run([
        objcopy,
        "--remove-section=__DATA,__mod_init_func",
        "--globalize-symbol=__GLOBAL__sub_I_XringUfsRoot.cpp",
        str(raw_o),
        str(late_o),
    ], env=env, check=True)
    kt.check_object(late_o.read_bytes(), late_o.name)
    print(f"XRING_UFS_ROOT_AUDIT=PASS (size={late_o.stat().st_size} B, 190/190 PAC MATCH vs 24A446 {kc_audit['vtable_va']})")


if __name__ == "__main__":
    main()
