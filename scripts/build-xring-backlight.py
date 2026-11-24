#!/usr/bin/env python3
"""Run host ASan/UBSan tests and compile XringGpio + XringI2c + XringBacklight into libXringBacklight.a."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compile_unit(record: dict, tree: Path, source: Path, obj: Path, extra_inc: list[Path], log_path: Path) -> None:
    arguments = record["arguments"]
    command: list[str] = []
    i = 0
    while i < len(arguments):
        val = arguments[i]
        if val == record["file"]:
            command.append(str(source))
        elif val == "-o":
            command.extend(["-o", str(obj)])
            i += 1
        elif val == "-Xclang" and i + 1 < len(arguments) and arguments[i + 1].startswith("-W"):
            i += 1
        elif not val.startswith("-W"):
            command.append(val)
        i += 1

    command.extend([
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wno-unused-parameter",
        "-Wno-c99-designator",
        "-Wno-missing-designated-field-initializers",
        "-Wno-reorder-init-list",
        "-Wno-deprecated-enum-enum-conversion",
        "-Wno-unnecessary-virtual-specifier",
        "-I", str(tree / ".cache/xnu-work/osfmk"),
    ])
    for inc in extra_inc:
        command.extend(["-I", str(inc)])

    res = subprocess.run(command, cwd=record["directory"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    log_path.write_text(res.stdout)
    if res.returncode != 0:
        sys.stderr.write(f"=== COMPILE FAILED: {source.name} ===\n")
        sys.stderr.write(res.stdout[-4000:])
        raise SystemExit(res.returncode)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tree", required=True, type=Path, help="Built UniXNU working tree")
    parser.add_argument("--common", required=True, type=Path, help="Path to source/UniXNU-xring-o1-common")
    parser.add_argument("--violin", required=True, type=Path, help="Path to source/UniXNU-violin")
    parser.add_argument("--out", required=True, type=Path, help="Output directory")
    args = parser.parse_args()

    tree = args.tree.resolve()
    common = args.common.resolve()
    violin = args.violin.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    # 1. Host ASan/UBSan unit test for Ktz8866Math.h
    bl_dir = violin / "drivers/XringBacklight"
    test_src = bl_dir / "test_ktz8866_math.c"
    test_bin = out / "test_ktz8866_math"
    host_env = dict(os.environ)
    host_env["PATH"] = "/usr/bin:/bin"
    subprocess.run(
        ["/usr/bin/cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=address,undefined", "-I", str(bl_dir),
         str(test_src), "-o", str(test_bin)],
        env=host_env,
        check=True,
    )
    test_out = subprocess.run([str(test_bin)], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(test_out.stdout.strip())

    # 2. Cross-compile arm64e-apple-ios27.0 kernel objects against XNU compile recipe
    sys.path.insert(0, str(tree / "scripts"))
    from kernel_target import TRIPLE, check_object  # type: ignore

    recipe = tree / "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json"
    if not recipe.is_file():
        raise SystemExit(f"Missing compile recipe: {recipe}")
    record = json.loads(recipe.read_text().strip().rstrip(","))

    gpio_dir = common / "drivers/XringGpio"
    i2c_dir = common / "drivers/XringI2c"
    extra_inc = [gpio_dir, i2c_dir, bl_dir]

    units = [
        ("XringGpio", gpio_dir / "XringGpio.cpp"),
        ("XringI2c", i2c_dir / "XringI2c.cpp"),
        ("XringBacklight", bl_dir / "XringBacklight.cpp"),
    ]
    objs: list[Path] = []
    report_objs: dict[str, dict[str, object]] = {}
    for name, src in units:
        obj = out / f"{name}.o"
        compile_unit(record, tree, src, obj, extra_inc, out / f"{name}.compile.log")
        check_object(obj.read_bytes(), name)
        objs.append(obj)
        report_objs[name] = {
            "source": str(src),
            "object": str(obj),
            "bytes": obj.stat().st_size,
            "sha256": sha256_file(obj),
        }

    archive = out / "libXringBacklight.a"
    archive.unlink(missing_ok=True)
    subprocess.run(["xcrun", "ar", "rcs", str(archive), *[str(o) for o in objs]], check=True)
    subprocess.run(["xcrun", "ranlib", str(archive)], check=True)

    report = {
        "triple": TRIPLE,
        "archive": str(archive),
        "archive_bytes": archive.stat().st_size,
        "archive_sha256": sha256_file(archive),
        "host_unit_test": test_out.stdout.strip(),
        "objects": report_objs,
    }
    (out / "xring-backlight-build-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"XringBacklight: -Werror build & {TRIPLE} audit passed -> {archive} ({archive.stat().st_size} B)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
