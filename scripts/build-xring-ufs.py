#!/usr/bin/env python3
"""Compile the read-only XRING O1 UFS 4.0 driver (XringUfs) against the built arm64e XNU tree."""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tree", required=True, type=Path, help="Built UniXNU working tree")
    parser.add_argument("--source", required=True, type=Path, help="Path to XringUfs.cpp")
    parser.add_argument("--out", required=True, type=Path, help="Output directory for XringUfs.o and libXringUfs.a")
    args = parser.parse_args()

    tree = args.tree.resolve()
    source = args.source.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    sys.path.insert(0, str(tree / "scripts"))
    from kernel_target import TRIPLE, check_object  # type: ignore

    recipe = tree / "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json"
    if not recipe.is_file():
        raise SystemExit(f"Missing compile recipe: {recipe}")
    record = json.loads(recipe.read_text().strip().rstrip(","))

    obj = out / "XringUfs.o"
    archive = out / "libXringUfs.a"
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

    (out / "xring-ufs-compile-command.json").write_text(json.dumps(command, indent=2) + "\n")
    res = subprocess.run(command, cwd=record["directory"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    (out / "xring-ufs-compile.log").write_text(res.stdout)
    if res.returncode != 0:
        sys.stderr.write(res.stdout[-4000:])
        return res.returncode

    check_object(obj.read_bytes(), "XringUfs")
    archive.unlink(missing_ok=True)
    subprocess.run(["xcrun", "ar", "rcs", str(archive), str(obj)], check=True)
    subprocess.run(["xcrun", "ranlib", str(archive)], check=True)
    print(f"XringUfs: -Werror build and {TRIPLE} object audit passed -> {archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
