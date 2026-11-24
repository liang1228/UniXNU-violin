#!/usr/bin/env python3
"""WSL2 Linux .so VerifiedRoot RSA-3072 policy builder & host verifier for violin.

Zero-upstream-edit counterpart of source/UniXNU/scripts/make-root-policies.py +
kits/VerifiedRoot/tests/check.py for Linux/WSL2 hosts:
  1. Compiles kits/VerifiedRoot/{src/verified_root.c,tests/openssl_provider.c}
     into a Linux shared library (verified-root.so) against OpenSSL 3.
  2. Cross-compiles kits/VerifiedRoot/src/verified_root.c for arm64e-apple-ios27.0
     and audits the object via kernel_target.check_object().
  3. Runs all 10 upstream security test groups (positive + negative RSA-3072
     signature, rollback, truncation, key-ID spoofing, block tamper, split header).
  4. Signs and verifies every --window NAME=IMAGE:VOLUME_UUID (and/or synthetic
     --selftest-image-mib N), producing:
       - <output>/<NAME>/{manifest.header.bin, trusted-key.bin, verification.json}
       - <work>/verified-root-<NAME>/{manifest.bin, hashes.bin} (<NAME>.vroot)
       - <output>/RootAnchor.c (const uint8_t verified_root_key[395])
       - <output>/root-policies.bin (VROOTB01 multi-window bundle)
"""
import argparse
import ctypes
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import uuid


class VrView(ctypes.Structure):
    _fields_ = [
        ("hashes", ctypes.c_void_p),
        ("image_bytes", ctypes.c_uint64),
        ("block_count", ctypes.c_uint64),
        ("generation", ctypes.c_uint64),
        ("volume_uuid", ctypes.c_uint8 * 16),
        ("image_sha256", ctypes.c_uint8 * 32),
    ]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def host_clean_env() -> dict:
    env = dict(os.environ)
    env["PATH"] = "/usr/bin:/bin"
    return env


def ensure_owner_keys(keys_dir: Path, env: dict):
    keys_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(keys_dir, 0o700)
    for name in ("owner", "other"):
        priv = keys_dir / f"{name}.pem"
        pub = keys_dir / f"{name}-public.pem"
        if not priv.exists():
            fd = os.open(priv, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            subprocess.run(
                ["/usr/bin/openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(priv)],
                check=True,
                capture_output=True,
                env=env,
            )
        os.chmod(priv, 0o600)
        subprocess.run(
            ["/usr/bin/openssl", "pkey", "-in", str(priv), "-pubout", "-out", str(pub)],
            check=True,
            capture_output=True,
            env=env,
        )


def build_host_so(kit: Path, out_dir: Path, env: dict) -> Path:
    if not Path("/usr/include/openssl/evp.h").is_file():
        raise SystemExit("OpenSSL 3 headers not found at /usr/include/openssl/evp.h (install libssl-dev)")
    lib = out_dir / "verified-root.so"
    cmd = [
        "/usr/bin/cc",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-shared",
        "-fPIC",
        "-I",
        str(kit / "include"),
        str(kit / "src/verified_root.c"),
        str(kit / "tests/openssl_provider.c"),
        "-lcrypto",
        "-o",
        str(lib),
    ]
    subprocess.run(cmd, check=True, env=env)
    return lib


def cross_compile_arm64e(kit: Path, tree: Path, out_dir: Path, unixnu: Path) -> Path:
    obj_record = json.loads(
        (tree / "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/osfmk/DEVELOPMENT/startup.o.json")
        .read_text()
        .strip()
        .rstrip(",")
    )
    clang = obj_record["arguments"][0]
    sdk = None
    args = obj_record["arguments"]
    for i, a in enumerate(args):
        if a == "-isysroot" and i + 1 < len(args):
            sdk = args[i + 1]
            break
    out_obj = out_dir / "verified-root-arm64e.o"
    cmd = [
        clang,
        "-target",
        "arm64e-apple-ios27.0",
        "-std=c11",
        "-ffreestanding",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I",
        str(kit / "include"),
        "-c",
        str(kit / "src/verified_root.c"),
        "-o",
        str(out_obj),
    ]
    if sdk:
        cmd[3:3] = ["-isysroot", sdk]
    subprocess.run(cmd, check=True)
    os.environ["UNIXNU_XNU_ARCH"] = "arm64e"
    os.environ["UNIXNU_IOS_VERSION"] = "27.0.1"
    kt = load_module("kernel_target", unixnu / "scripts/kernel_target.py")
    kt.check_object(out_obj.read_bytes(), "verified_root.c")
    return out_obj


def load_native_lib(lib: Path):
    native = ctypes.CDLL(str(lib.resolve()))
    native.vr_host_open.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(VrView)]
    native.vr_host_open.restype = ctypes.c_int
    native.vr_host_open_header.argtypes = native.vr_host_open.argtypes
    native.vr_host_open_header.restype = ctypes.c_int
    native.vr_host_block.argtypes = [ctypes.POINTER(VrView), ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t]
    native.vr_host_block.restype = ctypes.c_int
    return native


def run_security_suite(native, manifest_mod, keys_dir: Path, host_dir: Path) -> list[str]:
    data = bytes((i * 23 + i // 4096) & 255 for i in range(4096 * 3 + 512))
    signed_dir = host_dir / "signed"
    record = manifest_mod.make(
        io.BytesIO(data),
        len(data),
        keys_dir / "owner.pem",
        keys_dir / "owner-public.pem",
        uuid.UUID("01e286f1-f4dd-4b2f-99d9-4973337fc788"),
        7,
        signed_dir,
    )
    envelope = (signed_dir / "manifest.bin").read_bytes()
    key = (signed_dir / "trusted-key.bin").read_bytes()
    other_key = manifest_mod.public_anchor(keys_dir / "other-public.pem")
    assert len(key) == 395
    hold = []
    checks = []

    def opened(blob, anchor=key, generation=7, expected=0):
        enc = ctypes.create_string_buffer(blob)
        anc = ctypes.create_string_buffer(anchor)
        view = VrView()
        rc = native.vr_host_open(enc, len(blob), anc, generation, ctypes.byref(view))
        assert rc == expected, f"vr_host_open rc={rc} expected={expected}"
        if rc:
            assert not view.hashes and view.image_bytes == 0
        hold.extend((enc, anc))
        return view

    view = opened(envelope)
    assert view.image_bytes == len(data) and view.block_count == 4 and view.generation == 7
    assert bytes(view.volume_uuid) == uuid.UUID(record["volume_uuid"]).bytes
    checks.append("real RSA3072-SHA256 verification and signed metadata")

    for idx in range(4):
        blk = data[idx * 4096 : (idx + 1) * 4096]
        assert native.vr_host_block(ctypes.byref(view), idx, blk, len(blk)) == 0
    checks.append("all original blocks including exact 512-byte tail")

    for idx in range(4):
        blk = bytearray(data[idx * 4096 : (idx + 1) * 4096])
        blk[0] ^= 1
        assert native.vr_host_block(ctypes.byref(view), idx, bytes(blk), len(blk)) == 5
    checks.append("one-byte mutation refused in every block")

    assert native.vr_host_block(ctypes.byref(view), 1, data[:4096], 4096) == 5
    assert native.vr_host_block(ctypes.byref(view), 4, data[:4096], 4096) == 5
    assert native.vr_host_block(ctypes.byref(view), 0, data[:512], 512) == 5
    checks.append("block substitution, out-of-range index and partial-block reads refused")

    for off, exp in ((40, 3), (160, 3), (544, 4)):
        changed = bytearray(envelope)
        changed[off] ^= 1
        opened(bytes(changed), expected=exp)
    checks.append("signed UUID/header, RSA signature and hash-table mutation refused")

    opened(envelope, anchor=other_key, expected=2)
    opened(envelope, generation=8, expected=1)
    opened(envelope, generation=0, expected=1)
    opened(envelope[:-1], expected=1)
    opened(envelope + b"\0", expected=1)
    checks.append("wrong anchor, rollback generation, truncation and trailing bytes refused")

    changed = bytearray(envelope)
    changed[120:152] = hashlib.sha256(other_key).digest()
    opened(bytes(changed), anchor=other_key, expected=3)
    checks.append("attacker-selected key ID cannot bypass RSA signature")

    def header_opened(blob, anchor=key, generation=7, expected=0):
        enc = ctypes.create_string_buffer(blob)
        anc = ctypes.create_string_buffer(anchor)
        view_h = VrView()
        rc = native.vr_host_open_header(enc, len(blob), anc, generation, ctypes.byref(view_h))
        assert rc == expected, f"vr_host_open_header rc={rc} expected={expected}"
        assert not view_h.hashes
        if rc:
            assert view_h.image_bytes == 0
        hold.extend((enc, anc))
        return view_h

    header = envelope[:544]
    vh = header_opened(header)
    assert vh.image_bytes == len(data) and vh.block_count == 4
    for off, exp in ((40, 3), (160, 3)):
        changed = bytearray(header)
        changed[off] ^= 1
        header_opened(bytes(changed), expected=exp)
    header_opened(header, anchor=other_key, expected=2)
    header_opened(header, generation=8, expected=1)
    header_opened(envelope, expected=1)
    header_opened(header[:-1], expected=1)
    checks.append("signed 544-byte header authenticated standalone; mutation/key/rollback/size refused")

    table = envelope[544:]
    bad_table = bytearray(table)
    bad_table[0] ^= 1
    opened(header + bytes(bad_table), expected=4)
    opened(header + table, expected=0)
    checks.append("split hash table accepted iff matching signed digest")
    return checks


def sign_and_verify_window(
    name: str,
    image: Path,
    volume_uuid: str,
    generation: int,
    kit: Path,
    keys_dir: Path,
    lib: Path,
    native,
    work_root: Path,
    out_root: Path,
    env: dict,
    run_tamper_check: bool = True,
) -> tuple[bytes, bytes, dict]:
    work = work_root / f"verified-root-{name}"
    if work.exists():
        shutil.rmtree(work)
    subprocess.run(
        [
            sys.executable,
            str(kit / "tools/manifest.py"),
            "--image",
            str(image),
            "--private-key",
            str(keys_dir / "owner.pem"),
            "--public-key",
            str(keys_dir / "owner-public.pem"),
            "--volume-uuid",
            volume_uuid,
            "--generation",
            str(generation),
            "--output",
            str(work),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        env=env,
    )
    report_path = work / "verification.json"
    subprocess.run(
        [
            sys.executable,
            str(kit / "tools/verify_image.py"),
            "--library",
            str(lib),
            "--manifest",
            str(work / "manifest.bin"),
            "--trusted-key",
            str(work / "trusted-key.bin"),
            "--image",
            str(image),
            "--volume-uuid",
            volume_uuid,
            "--minimum-generation",
            str(generation),
            "--output",
            str(report_path),
        ],
        check=True,
        env=env,
    )
    envelope = (work / "manifest.bin").read_bytes()
    key = (work / "trusted-key.bin").read_bytes()
    record = json.loads(report_path.read_text())
    if (
        record["volume_uuid"] != volume_uuid
        or envelope[56:88].hex() != record["image_sha256"]
        or len(envelope) != 544 + 32 * record["blocks_verified"]
    ):
        raise SystemExit(f"{name}: signed manifest does not match {image}")

    tamper_checked = []
    if run_tamper_check:
        enc = ctypes.create_string_buffer(envelope)
        anc = ctypes.create_string_buffer(key)
        view = VrView()
        rc = native.vr_host_open(enc, len(envelope), anc, generation, ctypes.byref(view))
        assert rc == 0, f"{name}: vr_host_open failed rc={rc}"
        probe_indices = sorted({0, view.block_count // 2, view.block_count - 1})
        with image.open("rb") as f:
            for idx in probe_indices:
                f.seek(idx * 4096)
                blk = bytearray(f.read(min(4096, view.image_bytes - idx * 4096)))
                assert native.vr_host_block(ctypes.byref(view), idx, bytes(blk), len(blk)) == 0
                blk[len(blk) // 2] ^= 0x80
                assert native.vr_host_block(ctypes.byref(view), idx, bytes(blk), len(blk)) == 5
                tamper_checked.append(idx)
        record["tamper_negative_blocks_refused"] = tamper_checked

    dest = out_root / name
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "manifest.header.bin").write_bytes(envelope[:544])
    shutil.copyfile(work / "trusted-key.bin", dest / "trusted-key.bin")
    (dest / "verification.json").write_text(json.dumps(record, indent=2) + "\n")
    return envelope, key, record


def build_vrootb01_bundle(entries: list[bytes]) -> bytes:
    cursor = 32 + 16 * len(entries)
    table = bytearray()
    for data in entries:
        table += struct.pack("<QQ", cursor, len(data))
        cursor += len(data)
    return struct.pack("<8sQQQ", b"VROOTB01", 1, len(entries), cursor) + bytes(table) + b"".join(entries)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--unixnu", type=Path, required=True, help="Path to upstream source/UniXNU")
    parser.add_argument("--tree", type=Path, required=True, help="Path to resolved violin XNU build tree")
    parser.add_argument("--work", type=Path, required=True, help="Working directory for verified-root host/tables")
    parser.add_argument("--output", type=Path, required=True, help="Output policy directory")
    parser.add_argument("--window", action="append", default=[], metavar="NAME=IMAGE:VOLUME_UUID")
    parser.add_argument("--generation", type=int, default=1)
    parser.add_argument("--tables-in-userdata", action="store_true", help="Pack 544-byte signed headers only in root-policies.bin")
    parser.add_argument("--selftest-image-mib", type=int, default=0, help="Generate and verify a synthetic N MiB image window")
    args = parser.parse_args()

    unixnu = args.unixnu.resolve()
    tree = args.tree.resolve()
    work_root = args.work.resolve()
    out_root = args.output.resolve()
    kit = unixnu / "kits/VerifiedRoot"
    host_dir = work_root / "verified-root-host"
    host_dir.mkdir(parents=True, exist_ok=True)
    out_root.mkdir(parents=True, exist_ok=True)

    env = host_clean_env()
    ensure_owner_keys(host_dir / "keys", env)
    lib = build_host_so(kit, host_dir, env)
    arm64e_obj = cross_compile_arm64e(kit, tree, host_dir, unixnu)
    manifest_mod = load_module("manifest", kit / "tools/manifest.py")
    native = load_native_lib(lib)
    suite_checks = run_security_suite(native, manifest_mod, host_dir / "keys", host_dir)

    windows = list(args.window)
    if args.selftest_image_mib > 0:
        synth_img = work_root / f"synthetic-root-{args.selftest_image_mib}m.img"
        total_bytes = args.selftest_image_mib * 1024 * 1024
        chunk = bytes(((i * 131 + (i >> 8) * 17) & 0xFF) for i in range(65536))
        with synth_img.open("wb") as f:
            rem = total_bytes
            blk_idx = 0
            while rem > 0:
                buf = bytearray(chunk[: min(len(chunk), rem)])
                struct.pack_into("<Q", buf, 0, blk_idx)
                f.write(buf)
                rem -= len(buf)
                blk_idx += 1
        windows.append(f"SynthOS={synth_img}:11111111-2222-4333-8444-555555555555")

    if not windows:
        parser.error("Provide at least one --window NAME=IMAGE:VOLUME_UUID or --selftest-image-mib N")

    anchors = set()
    bundle_entries = []
    window_reports = {}
    key_bytes = None
    for spec in windows:
        name, sep, rest = spec.partition("=")
        img_str, sep2, vol_str = rest.rpartition(":")
        if not sep or not sep2 or not name or "/" in name:
            parser.error(f"--window {spec}: expected NAME=IMAGE:VOLUME_UUID")
        img_path = Path(img_str).resolve()
        vol_uuid = str(uuid.UUID(vol_str)).upper()
        if not img_path.is_file():
            parser.error(f"{img_path}: not a regular file")
        env_bytes, key_bytes, rec = sign_and_verify_window(
            name, img_path, vol_uuid, args.generation, kit, host_dir / "keys", lib, native, work_root, out_root, env
        )
        anchors.add(sha256_bytes(key_bytes))
        bundle_entries.append(env_bytes[:544] if args.tables_in_userdata else env_bytes)
        window_reports[name] = rec

    if len(anchors) != 1 or key_bytes is None:
        raise SystemExit("Windows were not signed by a single consistent owner key")

    bundle = build_vrootb01_bundle(bundle_entries)
    bundle_path = out_root / "root-policies.bin"
    bundle_path.write_bytes(bundle)

    anchor_c = out_root / "RootAnchor.c"
    anchor_c.write_text(
        "#include <stdint.h>\n"
        "const uint8_t verified_root_key[395] = {"
        + ",".join(str(b) for b in key_bytes)
        + "};\n"
    )

    summary = {
        "host_library": str(lib),
        "host_library_sha256": sha256_file(lib),
        "arm64e_object": str(arm64e_obj),
        "arm64e_object_sha256": sha256_file(arm64e_obj),
        "security_suite_groups_passed": len(suite_checks),
        "security_suite_checks": suite_checks,
        "trusted_key_sha256": next(iter(anchors)),
        "tables_in_userdata": args.tables_in_userdata,
        "policy_bundle": str(bundle_path),
        "policy_bundle_bytes": len(bundle),
        "policy_bundle_sha256": sha256_bytes(bundle),
        "root_anchor_c": str(anchor_c),
        "windows": window_reports,
        "host_only": True,
    }
    (out_root / "verified-root-report.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(
        f"PASS: verified-root.so + arm64e obj + {len(suite_checks)} security suites + "
        f"{len(window_reports)} window(s) (bundle={len(bundle)} B, sha256={summary['policy_bundle_sha256'][:16]}...)"
    )


if __name__ == "__main__":
    main()
