#!/usr/bin/env python3
"""Prepare compact, verified iPadOS 27.0.1 (24A446) APFS seeds on macos-26.

Runs on a private GitHub Actions macos-26 runner (zero edits to upstream UniXNU).
Produces ONLY compact APFS DBRDISK1 seeds, trustcaches, and verified cryptographic
metadata (< 20 MiB total; zero Apple .dmg files are retained for upload):
  1. apfs-test-8m.dbr             (8 MiB -layout NONE APFS + hello.txt)
  2. apfs-test-gpt-8m.dbr         (8 MiB -layout GPTSPUD APFS + hello.txt)
  3. data-24A446-128m-skipsetup.dbr (128 MiB volatile-RAM-safe Data seed)
  4. data-24A446-16g-skipsetup.dbr  (16 GiB persistent-store Data seed via upstream make-data-seed.py)
  5. 043-68950-668.dmg.aea.trustcache (StaticTrustCache)
  6. 043-69086-713.dmg.aea.trustcache (Cryptex1,SystemTrustCache)
  7. macos26-assets-manifest.json (container/volume UUIDs + verified OS/SystemOS raw SHA-256)
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid
import zipfile


CHUNK = 8 << 20


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(*args, check=True):
    res = subprocess.run(list(args), capture_output=True, text=True)
    if check and res.returncode != 0:
        sys.stderr.write(res.stdout or "")
        sys.stderr.write(res.stderr or "")
        raise SystemExit(f"Command failed rc={res.returncode}: {args}")
    return res.stdout


def query_apfs_uuids(dev_entry: str, timeout: float = 30.0) -> dict:
    """Return container_uuid and list of {name, uuid, dev} for an attached physical store."""
    store = dev_entry.removeprefix("/dev/")
    deadline = time.monotonic() + timeout
    last_err = ""
    while time.monotonic() < deadline:
        res = subprocess.run(["diskutil", "apfs", "list", "-plist"], capture_output=True)
        if res.returncode == 0:
            listing = plistlib.loads(res.stdout)
            for c in listing.get("Containers", []):
                stores = [p.get("DeviceIdentifier", "") for p in c.get("PhysicalStores", [])]
                if any(s == store or s.startswith(store + "s") for s in stores):
                    vols = [
                        {
                            "name": v.get("Name", ""),
                            "uuid": str(v.get("APFSVolumeUUID", "")).upper(),
                            "device": v.get("DeviceIdentifier", ""),
                        }
                        for v in c.get("Volumes", [])
                    ]
                    if vols:
                        return {
                            "container_uuid": str(c.get("APFSContainerUUID", "")).upper(),
                            "container_ref": c.get("ContainerReference", ""),
                            "volumes": vols,
                        }
        else:
            last_err = res.stderr.decode(errors="replace")
        time.sleep(0.5)
    raise SystemExit(f"Timed out querying APFS UUIDs on {dev_entry}: {last_err}")


def inspect_dbr_apfs_uuids(dbr_path: Path, packed_ramdisk, scratch: Path) -> dict:
    """Temporarily materialize a DBRDISK1 seed as a sparse raw file to read its APFS UUIDs."""
    blob = dbr_path.read_bytes()
    logical, extents = packed_ramdisk.regions(blob)
    raw = scratch / (dbr_path.stem + ".inspect.raw")
    with raw.open("wb") as f:
        f.truncate(logical)
        for off, data in extents:
            f.seek(off)
            f.write(data)
    out = subprocess.check_output(
        ["hdiutil", "attach", "-imagekey", "diskimage-class=CRawDiskImage", "-readonly", "-nomount", "-nobrowse", "-plist", str(raw)]
    )
    attached = plistlib.loads(out)
    whole = next(e["dev-entry"] for e in attached["system-entities"] if re.fullmatch(r"/dev/disk\d+", e.get("dev-entry", "")))
    try:
        info = query_apfs_uuids(whole)
    finally:
        subprocess.run(["hdiutil", "detach", whole, "-force"], capture_output=True)
        raw.unlink(missing_ok=True)
    return info


def make_test_apfs_seed(
    out_dbr: Path,
    layout: str,
    volname: str,
    marker_text: str,
    packed_ramdisk,
    work: Path,
) -> dict:
    raw = work / f"{volname}.cdr"
    raw.unlink(missing_ok=True)
    run("hdiutil", "create", "-size", "8m", "-layout", layout, "-fs", "APFS", "-volname", volname, "-type", "UDTO", str(raw))
    mnt = work / f"mnt-{volname}"
    mnt.mkdir(parents=True, exist_ok=True)
    attach_cmd = ["hdiutil", "attach", "-nobrowse", "-owners", "off", "-plist", str(raw)]
    if layout == "NONE":
        attach_cmd[4:4] = ["-mountpoint", str(mnt)]
    attached = plistlib.loads(subprocess.check_output(attach_cmd))
    whole = next(e["dev-entry"] for e in attached["system-entities"] if re.fullmatch(r"/dev/disk\d+", e.get("dev-entry", "")))
    try:
        apfs_info = query_apfs_uuids(whole)
        actual_mnt = next(
            (Path(e["mount-point"]) for e in attached["system-entities"] if e.get("mount-point")),
            mnt,
        )
        (actual_mnt / "hello.txt").write_text(marker_text)
        os.sync()
    finally:
        run("hdiutil", "detach", whole, "-force")

    meta = packed_ramdisk.pack(raw, out_dbr)
    raw.unlink(missing_ok=True)
    return {
        "file": out_dbr.name,
        "layout": layout,
        "volname": volname,
        "apfs": apfs_info,
        **meta,
        "encoded_sha256": sha256_file(out_dbr),
        "encoded_bytes": out_dbr.stat().st_size,
    }


def merge_plist(mount: Path, home: str, name: str, values: dict):
    path = mount / home / "Library/Preferences" / f"{name}.plist"
    path.parent.mkdir(parents=True, exist_ok=True)
    content = plistlib.loads(path.read_bytes()) if path.is_file() else {}
    content.update(values)
    path.write_bytes(plistlib.dumps(content, fmt=plistlib.FMT_BINARY))
    path.chmod(0o644)


def make_volatile_data_seed(
    os_mount: Path,
    out_dbr: Path,
    size_mib: int,
    build: str,
    packed_ramdisk,
    work: Path,
) -> dict:
    """Create a <=2 GiB volatile-RAM-compatible Data seed matching upstream make-data-seed.py."""
    source = os_mount / "private/var"
    if not (os_mount / "sbin/launchd").is_file() or not source.is_dir():
        raise SystemExit(f"{os_mount}: not a mounted IPSW OS volume")
    raw = work / f"data-{size_mib}m.cdr"
    raw.unlink(missing_ok=True)
    run("hdiutil", "create", "-size", f"{size_mib}m", "-layout", "NONE", "-fs", "APFS", "-volname", "Data", "-type", "UDTO", str(raw))
    mnt = work / f"mnt-data-{size_mib}m"
    mnt.mkdir(parents=True, exist_ok=True)
    attached = plistlib.loads(
        subprocess.check_output(["hdiutil", "attach", "-nobrowse", "-owners", "off", "-mountpoint", str(mnt), "-plist", str(raw)])
    )
    whole = next(e["dev-entry"] for e in attached["system-entities"] if re.fullmatch(r"/dev/disk\d+", e.get("dev-entry", "")))
    try:
        apfs_info = query_apfs_uuids(whole)
        for current, dirs, files in os.walk(source, followlinks=False):
            dirs[:] = [n for n in dirs if n != "staged_system_apps"]
            dest = mnt / Path(current).relative_to(source)
            dest.mkdir(exist_ok=True)
            dest.chmod(stat.S_IMODE(Path(current).stat().st_mode))
            for name in list(dirs) + files:
                src, dst = Path(current) / name, dest / name
                if src.is_symlink():
                    dst.symlink_to(os.readlink(src))
                    if name in dirs:
                        dirs.remove(name)
                elif src.is_file():
                    shutil.copy2(src, dst)
        for rel in (
            "keybags", "mobile/tmp", "tmp", "run",
            "containers/Bundle", "containers/Data/System",
            "containers/Shared/SystemGroup", "containers/Temp",
        ):
            (mnt / rel).mkdir(parents=True, exist_ok=True)
        (mnt / "tmp").chmod(0o1777)
        # Apply identical --skip-setup & framebuffer preferences as upstream make-data-seed.py
        merge_plist(mnt, "mobile", "com.apple.purplebuddy", dict(
            SetupDone=True, SetupFinishedAllSteps=True, SetupVersion=11, daemonizeNeedsToRun=False))
        merge_plist(mnt, "mobile", "com.apple.purplebuddy.notbackedup", {
            n: False for n in (
                "ShouldRunDiagnosticsMiniBuddy", "ShouldRunHSA2MiniBuddy",
                "ShouldRunKeychainSyncMiniBuddy", "ShouldRunMesaMiniBuddy",
                "ShouldRunPaymentMiniBuddy", "ShouldRunStandardMiniBuddy", "SilentICDPUpgrade",
            )
        })
        merge_plist(mnt, "mobile", "com.apple.managedconfiguration.notbackedup",
                    dict(LockdownActivationIndicatesCloudConfigurationAvailable=False))
        merge_plist(mnt, "mobile", "com.apple.springboard", dict(
            BKNoWatchdogs=True,
            FBLaunchWatchdogExceptions={"com.apple.purplebuddy": 100.0},
            MCForceShowCloudConfigurationUI=False,
        ))
        merge_plist(mnt, "mobile", "com.apple.migration", dict(
            LastSystemVersion=build,
            DMUserDataDisposition=dict(SyntheticDidUpgrade=False, buildVersion=build),
        ))
        for home in ("root", "mobile"):
            for name in ("backboardd", ".GlobalPreferences"):
                merge_plist(mnt, home, name, dict(
                    CAEnableDeepFramebuffer=False,
                    CAEnableFramebufferCompression=False,
                    CAEnableIOSurfaceCompression=False,
                ))
        os.sync()
    finally:
        run("hdiutil", "detach", whole, "-force")

    meta = packed_ramdisk.pack(raw, out_dbr)
    raw.unlink(missing_ok=True)
    return {
        "file": out_dbr.name,
        "layout": "NONE",
        "volname": "Data",
        "size_mib": size_mib,
        "skip_setup": True,
        "apfs": apfs_info,
        **meta,
        "encoded_sha256": sha256_file(out_dbr),
        "encoded_bytes": out_dbr.stat().st_size,
    }


def extract_ipsw_member(zf: zipfile.ZipFile, member: str, dst: Path) -> str:
    dst.parent.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    zi = zf.getinfo(member)
    size = zi.file_size
    done = 0
    t0 = last = time.monotonic()
    print(f"[ipsw] extracting {member} ({size / (1<<20):.1f} MiB)...", flush=True)
    with zf.open(member) as src, dst.open("wb") as out:
        while chunk := src.read(CHUNK):
            out.write(chunk)
            h.update(chunk)
            done += len(chunk)
            now = time.monotonic()
            if now - last >= 15 or done == size:
                spd = done / max(now - t0, 0.001) / (1 << 20)
                print(f"[ipsw] {member}: {100.0*done/size:.1f}% ({spd:.1f} MiB/s)", flush=True)
                last = now
    return h.hexdigest()


def decrypt_aea_macos(aea_path: Path) -> Path:
    plain = aea_path.with_suffix("")
    res = subprocess.run(["ipsw", "fw", "aea", "--key", str(aea_path)], capture_output=True, text=True)
    keys = [ln.strip() for ln in res.stdout.splitlines() if ln.strip().startswith("base64:")]
    if res.returncode != 0 or len(keys) != 1:
        raise SystemExit(f"ipsw fw aea --key failed for {aea_path.name}: {res.stderr[-400:]}")
    print(f"[aea] decrypting {aea_path.name} -> {plain.name}...", flush=True)
    dec = subprocess.run(["/usr/bin/aea", "decrypt", "-i", str(aea_path), "-o", str(plain), "-key-value", keys[0]],
                         capture_output=True, text=True)
    if dec.returncode != 0:
        plain.unlink(missing_ok=True)
        raise SystemExit(f"aea decrypt failed for {aea_path.name}: {dec.stderr[-400:]}")
    return plain


def verify_raw_dmg_blocks(dmg_path: Path, expected_sha256: str) -> dict:
    info_plist = plistlib.loads(subprocess.check_output(["hdiutil", "imageinfo", "-plist", str(dmg_path)]))
    total_bytes = int(info_plist["Size Information"]["Total Bytes"])
    out = subprocess.check_output(
        ["hdiutil", "attach", "-nomount", "-readonly", "-noverify", "-noautofsck", "-plist", str(dmg_path)]
    )
    attached = plistlib.loads(out)
    whole = next(e["dev-entry"] for e in attached["system-entities"] if re.fullmatch(r"/dev/disk\d+", e.get("dev-entry", "")))
    raw_dev = whole.replace("/dev/disk", "/dev/rdisk")
    h = hashlib.sha256()
    done = 0
    apfs_info = None
    try:
        try:
            apfs_info = query_apfs_uuids(whole, timeout=10.0)
        except SystemExit as exc:
            print(f"[warn] query_apfs_uuids on -nomount {dmg_path.name}: {exc}", flush=True)
        with open(raw_dev, "rb", buffering=0) as f:
            while done < total_bytes:
                want = min(CHUNK, total_bytes - done)
                data = f.read(want)
                if len(data) != want:
                    raise SystemExit(f"short read from {raw_dev} at {done}")
                h.update(data)
                done += want
    finally:
        subprocess.run(["hdiutil", "detach", whole, "-force"], capture_output=True)
    actual = h.hexdigest()
    if actual != expected_sha256:
        raise SystemExit(f"{dmg_path.name} raw SHA-256 mismatch: {actual} != {expected_sha256}")
    print(f"[verify] {dmg_path.name}: raw_bytes={total_bytes} sha256={actual} MATCH", flush=True)
    return {"raw_bytes": total_bytes, "raw_sha256": actual, "apfs": apfs_info}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--unixnu", type=Path, required=True)
    ap.add_argument("--work", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--verify-systemos", action="store_true", help="Also verify Cryptex1,SystemOS raw SHA-256")
    args = ap.parse_args()

    unixnu = args.unixnu.resolve()
    work = args.work.resolve()
    out = args.out.resolve()
    work.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)

    sys.path.insert(0, str(unixnu / "scripts"))
    sys.path.insert(0, str(unixnu / "drivers/DarwinBoot/Test"))
    from unixnu.ipsw import RangeFile
    import packed_ramdisk

    profile = tomllib.loads((unixnu / "profiles/os/ipados-27.0.1-24A446/profile.toml").read_text())
    ipsw_url = profile["ipsw"]["url"]
    build_id = profile["ipsw"]["build"]
    dev_class = profile["ipsw"]["device_class"]
    exp_os_sha = profile["root"]["os_image_sha256"]
    exp_sys_sha = profile["root"]["systemos_image_sha256"]

    manifest = {
        "build": build_id,
        "device_class": dev_class,
        "ipsw_url": ipsw_url,
        "seeds": {},
        "trustcaches": {},
        "verified_images": {},
    }

    # 1. Synthetic Stage-7H/6C APFS test seeds (zero Apple content, < 400 KiB total)
    print("=== 1. Building synthetic 8 MiB APFS test seeds ===", flush=True)
    manifest["seeds"]["apfs_test_8m"] = make_test_apfs_seed(
        out / "apfs-test-8m.dbr", "NONE", "ViolinApfsTest", "VIOLIN_APFS_LIVE_OK\n", packed_ramdisk, work
    )
    manifest["seeds"]["apfs_test_gpt_8m"] = make_test_apfs_seed(
        out / "apfs-test-gpt-8m.dbr", "GPTSPUD", "ViolinApfsGpt", "VIOLIN_APFS_GPT_OK\n", packed_ramdisk, work
    )

    # 2. Open remote 24A446 IPSW via HTTP Range requests
    print("=== 2. Opening remote 24A446 IPSW ===", flush=True)
    rf = RangeFile(ipsw_url)
    with zipfile.ZipFile(rf) as zf:
        bm = plistlib.loads(zf.read("BuildManifest.plist"))
        identity = next(
            ident for ident in bm["BuildIdentities"]
            if ident.get("Info", {}).get("DeviceClass") == dev_class
            and ident.get("Info", {}).get("RestoreBehavior") == "Erase"
        )
        man = identity["Manifest"]

        # 2a. Extract both trustcaches
        for comp in ("StaticTrustCache", "Cryptex1,SystemTrustCache"):
            member = man[comp]["Info"]["Path"]
            dst = out / Path(member).name
            digest = extract_ipsw_member(zf, member, dst)
            manifest["trustcaches"][comp] = {
                "file": dst.name,
                "member": member,
                "bytes": dst.stat().st_size,
                "sha256": digest,
            }

        # 2b. Extract & decrypt OS (.dmg.aea), verify raw SHA-256, build 128m + 16g Data seeds, then delete OS dmg!
        print("=== 3. Fetching & decrypting 24A446 OS DMG ===", flush=True)
        os_member = man["OS"]["Info"]["Path"]
        os_aea = work / Path(os_member).name
        os_aea_sha = extract_ipsw_member(zf, os_member, os_aea)
        os_dmg = decrypt_aea_macos(os_aea)
        os_aea.unlink()  # Free ~7.8 GiB immediately

        os_verify = verify_raw_dmg_blocks(os_dmg, exp_os_sha)
        os_verify["aea_member"] = os_member
        os_verify["aea_sha256"] = os_aea_sha
        os_verify["decrypted_dmg_bytes"] = os_dmg.stat().st_size
        os_verify["decrypted_dmg_sha256"] = sha256_file(os_dmg)
        manifest["verified_images"]["OS"] = os_verify

        # Mount OS DMG read-only to generate 128 MiB volatile + 16 GiB persistent Data seeds
        print("=== 4. Building 24A446 Data seeds (128 MiB volatile + 16 GiB persistent) ===", flush=True)
        os_mnt = work / "os-mount"
        os_mnt.mkdir(parents=True, exist_ok=True)
        attached = plistlib.loads(
            subprocess.check_output(["hdiutil", "attach", "-readonly", "-nobrowse", "-mountpoint", str(os_mnt), "-plist", str(os_dmg)])
        )
        os_whole = attached["system-entities"][0]["dev-entry"]
        try:
            manifest["seeds"]["data_24A446_128m"] = make_volatile_data_seed(
                os_mnt, out / "data-24A446-128m-skipsetup.dbr", 128, build_id, packed_ramdisk, work
            )
            seed_16g = out / "data-24A446-16g-skipsetup.dbr"
            subprocess.run(
                [
                    sys.executable,
                    str(unixnu / "scripts/make-data-seed.py"),
                    str(os_mnt),
                    str(seed_16g),
                    "--gib",
                    "16",
                    "--build",
                    build_id,
                    "--skip-setup",
                ],
                check=True,
            )
        finally:
            run("hdiutil", "detach", os_whole, "-force")
        os_dmg.unlink()  # Never retain 7.8 GiB DMG

        info_16g, _ = packed_ramdisk.inspect(seed_16g)
        apfs_16g = inspect_dbr_apfs_uuids(seed_16g, packed_ramdisk, work)
        manifest["seeds"]["data_24A446_16g"] = {
            "file": seed_16g.name,
            "layout": "NONE",
            "volname": "Data",
            "size_gib": 16,
            "skip_setup": True,
            "apfs": apfs_16g,
            **info_16g,
        }

        # 2c. Optional verification of Cryptex1,SystemOS raw SHA-256 (deleted immediately after verify)
        if args.verify_systemos:
            print("=== 5. Fetching & verifying Cryptex1,SystemOS ===", flush=True)
            sys_member = man["Cryptex1,SystemOS"]["Info"]["Path"]
            sys_aea = work / Path(sys_member).name
            sys_aea_sha = extract_ipsw_member(zf, sys_member, sys_aea)
            sys_dmg = decrypt_aea_macos(sys_aea)
            sys_aea.unlink()
            sys_verify = verify_raw_dmg_blocks(sys_dmg, exp_sys_sha)
            sys_verify["aea_member"] = sys_member
            sys_verify["aea_sha256"] = sys_aea_sha
            sys_verify["decrypted_dmg_bytes"] = sys_dmg.stat().st_size
            sys_verify["decrypted_dmg_sha256"] = sha256_file(sys_dmg)
            manifest["verified_images"]["SystemOS"] = sys_verify
            sys_dmg.unlink()

    # Final safety guard: assert zero .dmg/.aea files in output and total size < 100 MiB
    total_out = 0
    for p in sorted(out.iterdir()):
        if p.suffix in (".dmg", ".aea", ".cdr", ".raw"):
            raise SystemExit(f"REFUSED: unexpected large disk image in artifact dir: {p}")
        total_out += p.stat().st_size
    if total_out > 100 * 1024 * 1024:
        raise SystemExit(f"REFUSED: total artifact size {total_out} exceeds 100 MiB guard")

    manifest["total_artifact_bytes"] = total_out
    (out / "macos26-assets-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"PASS: prepared compact macos-26 assets ({total_out / (1<<20):.2f} MiB) in {out}", flush=True)


if __name__ == "__main__":
    main()
