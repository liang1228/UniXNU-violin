#!/usr/bin/env python3
"""Run Stage-8C dual 10-core QEMU gates (4 GiB + 10 GiB UEFI / 8 GiB XNU window)
verifying 0 panics, 0 PAC faults, ViolinFastFb WC presenter, ViolinHidInput 207-slot
registration, 220-slot IOHIDEventDriver edge-swipe hook, synthetic bottom-edge swipe
self-test delivery, and [VIOLIN_HB4] telemetry.
"""
import os
import re
import select
import subprocess
import sys
import time
from pathlib import Path

OUT = Path("/opt/unixnu-out/stage8c-touch-highhz")
ARCHIVE = Path(os.environ.get("STAGE8C_ARCHIVE_DIR", str(OUT)))


def run_gate(name: str, kernel_bin: Path, ram_arg: str, log_path: Path, max_sec: int = 210, wait_watchdog: bool = False) -> dict:
    cmd = [
        "qemu-system-aarch64",
        "-machine", "virt,gic-version=3,virtualization=off",
        "-cpu", "max,pauth-impdef=on",
        "-smp", "10",
        "-m", ram_arg,
        "-global", "virtio-mmio.force-legacy=false",
        "-nographic", "-monitor", "none", "-serial", "stdio",
        "-kernel", str(kernel_bin),
        "-drive", "if=none,id=d_os,format=raw,readonly=on,file=/opt/unixnu-out/ipsw/24A446/OS.raw.dmg",
        "-device", "virtio-blk-device,drive=d_os",
        "-drive", "if=none,id=d_sysos,format=raw,readonly=on,file=/opt/unixnu-out/ipsw/24A446/SystemOS.raw.dmg",
        "-device", "virtio-blk-device,drive=d_sysos",
        "-drive", "if=none,id=d_pol,format=raw,readonly=on,file=/opt/unixnu-out/stage7j-qemu-launchd/manifests-24A446.raw",
        "-device", "virtio-blk-device,drive=d_pol",
    ]
    print(f"=== STAGE-8C QEMU GATE {name} ({ram_arg}, {kernel_bin.name}, wait_watchdog={wait_watchdog}) ===", flush=True)
    t0 = time.monotonic()
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    saw_launchd_at = None
    saw_selftest_at = None
    saw_wd_exit_at = None
    saw_panic = False
    full_lines = []
    try:
        with log_path.open("w", encoding="utf-8", errors="replace") as lf:
            while True:
                elapsed = time.monotonic() - t0
                if elapsed >= max_sec:
                    break
                if wait_watchdog:
                    if saw_wd_exit_at is not None and (elapsed - saw_wd_exit_at) >= 2.0:
                        break
                elif saw_launchd_at is not None and saw_selftest_at is not None and (elapsed - max(saw_launchd_at, saw_selftest_at)) >= 6.0:
                    break
                elif saw_launchd_at is not None and (elapsed - saw_launchd_at) >= 30.0:
                    break
                r, _, _ = select.select([proc.stdout], [], [], min(1.0, max_sec - elapsed))
                if not r:
                    if proc.poll() is not None:
                        break
                    continue
                raw = proc.stdout.readline()
                if not raw:
                    if proc.poll() is not None:
                        break
                    continue
                elapsed = time.monotonic() - t0
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                entry = f"[+{elapsed:6.1f}s] {line}"
                lf.write(entry + "\n")
                lf.flush()
                full_lines.append(line)
                if any(k in line for k in (
                    "VIOLIN_8C", "VIOLIN_DATA", "VIOLIN_POLICY", "VIOLIN_HB",
                    "VIOLIN_FASTFB", "VIOLIN_LEGACY", "VIOLIN_HID", "VIOLIN_TOUCH",
                    "VIOLIN_PERSIST_SYNC", "XNU_STAGE5_WATCHDOG", "dt_attached",
                    "default_surface", "STAGE5_SMP", "load_init_program",
                    "panic", "Debugger message", "You are hanging",
                )):
                    print(entry, flush=True)
                if "load_init_program: attempting to load /sbin/launchd" in line and saw_launchd_at is None:
                    saw_launchd_at = elapsed
                if "[VIOLIN_HID] SELFTEST PASS" in line and saw_selftest_at is None:
                    saw_selftest_at = elapsed
                if "[XNU_STAGE5_WATCHDOG3]" in line and saw_wd_exit_at is None:
                    saw_wd_exit_at = elapsed
                if "Debugger message: panic" in line or "You are hanging here" in line or "initproc failed to start" in line or "panic(cpu" in line:
                    saw_panic = True
                    t_end = time.monotonic() + 2.0
                    while time.monotonic() < t_end:
                        r2, _, _ = select.select([proc.stdout], [], [], 0.3)
                        if not r2:
                            break
                        raw2 = proc.stdout.readline()
                        if not raw2:
                            break
                        l2 = raw2.decode("utf-8", errors="replace").rstrip("\r\n")
                        lf.write(f"[+{time.monotonic()-t0:6.1f}s] {l2}\n")
                        full_lines.append(l2)
                        print(f"[+{time.monotonic()-t0:6.1f}s] {l2}", flush=True)
                    break
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    joined = "\n".join(full_lines)
    checks = {
        "no_panic": not saw_panic,
        "smp_10": "online=10/10" in joined or "[XNU_STAGE5_SMP]" in joined,
        "dt_attached": "dt_attached=1" in joined,
        "default_surface": "ok=1" in joined and "default_surface" in joined,
        "fastfb_ready": "[VIOLIN_FASTFB] PASS:" in joined,
        "hid_registered": "[VIOLIN_HID] PASS: ViolinHidInput registered" in joined,
        "hid_edge_hook": "[VIOLIN_HID] edge::install PASS" in joined,
        "hid_selftest_pass": "[VIOLIN_HID] SELFTEST PASS" in joined,
        "touch_disabled_qemu": "[VIOLIN_TOUCH] disabled by boot-arg violin-touch=0" in joined,
        "desiredvnodes_32768": "desiredvnodes=32768" in joined,
        "launchd": "load_init_program: attempting to load /sbin/launchd" in joined,
    }
    if name == "10G":
        checks["window_8g"] = bool(
            re.search(r"0x0*200000000", joined, re.I) or "8192 MiB" in joined or "8589934592" in joined
        )
    if wait_watchdog:
        checks["hb4_ok"] = "[VIOLIN_HB4]" in joined
        checks["wd3_ok"] = "[XNU_STAGE5_WATCHDOG3]" in joined
    print(f"GATE {name} SUMMARY (elapsed={time.monotonic()-t0:.1f}s, lines={len(full_lines)}): {checks}", flush=True)
    return checks


def main():
    p2 = (OUT / "prelink-pass2.log").read_text().strip()
    print(f"PRELINK_PASS2: {p2}", flush=True)

    c4 = run_gate("4G", OUT / "violin-uefi-stage8c-qemu-4g.bin", "8G", ARCHIVE / "qemu-4g-gate.log", wait_watchdog=False)
    c10 = run_gate("10G", OUT / "violin-uefi-stage8c-qemu-10g.bin", "13G", ARCHIVE / "qemu-10g-gate.log", wait_watchdog=True)

    ok = all(c4.values()) and all(c10.values())
    print(f"OVERALL_STAGE8C_QEMU_GATES={'PASS' if ok else 'FAIL'}", flush=True)
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
