#!/usr/bin/env python3
"""Compile upstream NativeGOPPresenter.cpp (read-only) + ViolinGopProbe.cpp into libViolinGopPresenter.a."""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def compile_one(record: dict, tree: Path, source: Path, obj: Path, extra_inc: list[str]) -> None:
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
        command.extend(["-I", inc])

    res = subprocess.run(command, cwd=record["directory"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    obj.with_suffix(".compile.log").write_text(res.stdout)
    if res.returncode != 0:
        sys.stderr.write(f"Failed compiling {source}:\n{res.stdout[-4000:]}\n")
        raise SystemExit(res.returncode)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tree", required=True, type=Path, help="Built UniXNU working tree")
    parser.add_argument("--unixnu", required=True, type=Path, help="Clean upstream source/UniXNU root")
    parser.add_argument("--probe", required=True, type=Path, help="Path to ViolinGopProbe.cpp")
    parser.add_argument("--out", required=True, type=Path, help="Output directory")
    args = parser.parse_args()

    tree = args.tree.resolve()
    unixnu = args.unixnu.resolve()
    probe = args.probe.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    sys.path.insert(0, str(tree / "scripts"))
    from kernel_target import TRIPLE, check_object  # type: ignore

    recipe = tree / "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json"
    record = json.loads(recipe.read_text().strip().rstrip(","))

    gop_dir = unixnu / "drivers/GopFramebuffer"
    presenter_src = gop_dir / "NativeGOPPresenter.cpp"
    presenter_obj = out / "NativeGOPPresenter.o"
    probe_obj = out / "ViolinGopProbe.o"
    archive = out / "libViolinGopPresenter.a"

    compile_one(record, tree, presenter_src, presenter_obj, [str(gop_dir)])
    check_object(presenter_obj.read_bytes(), "NativeGOPPresenter")

    compile_one(record, tree, probe, probe_obj, [str(gop_dir)])
    check_object(probe_obj.read_bytes(), "ViolinGopProbe")

    archive.unlink(missing_ok=True)
    subprocess.run(["xcrun", "ar", "rcs", str(archive), str(presenter_obj), str(probe_obj)], check=True)
    subprocess.run(["xcrun", "ranlib", str(archive)], check=True)
    print(f"ViolinGopPresenter: -Werror build & {TRIPLE} object audit passed -> {archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
