# UniXNU-violin

UniXNU device port for **Xiaomi Pad 7S Pro** (`violin` / `O81A` / `XRING O1`, 10-core `arm64e`, 16 GiB RAM, 3200x2136 display), targeting `iPadOS 27` (`ipados-27.0.1-24A446`, primary) and `macOS 27` (`macos-27.3-26C5035r`, via `os_overrides`).

## Verified Bootable Release (`v0.1.0-stage8a-bootable`)

On real **Xiaomi Pad 7S Pro (`violin`)** hardware with unlocked bootloader (dual-booting alongside unmodified Android 17 on `slot a` via non-active `boot_b`):

- **Original `ipados-27.0.1-24A446` `SpringBoard` lockscreen boots and renders live** at native `3200x2136 @2x` (`1600x1068` logical points), displaying the date, clock, and Home indicator bar (`480` frames scanned out, `0` rejected, `9` graphics clients, `50.6 ms` min frame copy).
- **10/10 CPU cores online** (`2x Cortex-A520 + 6x Cortex-A725 + 2x Cortex-X925`), GIC-700, `38.4 MHz` timer, PSCI 1.1 warm reset.
- **270s 0-panic live run** crossing the XRING O1 256s hardware watchdog (`DW_APB_WDT @ 0xEC00C000`) via `xring-wdt-kick=1` (`CRASH=Normal`, dual-ring `ramoops` intact).
- **Strictly read-only UFS 4.1 `SHNGROOT v2`** (`XringUfsRoot`, 190/190 arm64e PAC slots, `11,772 MiB` verified reads, `rfail=0, ifail=0, wrej=0`) + **16 GiB sparse RAM Overlay `Data` volume** (`ViolinRamOverlayStore`, `886 MiB` absorbed, `0 ENOSPC`).
- **Dual `KTZ8866A` backlight** (`XringGpio` + `XringI2c` + `XringBacklight`), `APFS v3288.2.1`, `corecrypto v27.0` 19/19 FIPS, `AppleImage4`/`AMFI`/`Sandbox`/`TrustCache`/`AppleKeyStore`.

### Current Limitations (Stage-8A)

- **No interactive input yet** (SPI9 touch, Pogo keyboard `I2C10@0x4C`, and `XringDwc3` USB2-HS Device Slice 2 are planned for Stage-8B), so the device boots to and stays on the `SpringBoard` lockscreen.
- **No Mali GPU acceleration / Wi-Fi / BT / Audio** yet (display uses CPU software composition via `NativeLegacyDisplay`).
- **Zero Apple binaries included**: you must supply your own legally obtained `ipados-27.0.1-24A446` IPSW assets locally.

## Repository Layout (3 Public Repos + Upstream UniXNU)

Clone all four repositories as siblings under a common directory:

```sh
git clone https://github.com/UniXNU/UniXNU.git
git -C UniXNU checkout 8542980
git clone https://github.com/liang1228/UniXNU-xring-o1-common.git
git clone https://github.com/liang1228/UniXNU-violin.git
git clone https://github.com/liang1228/uefi-violin.git
```

| Repository | Role | Release Tag |
| --- | --- | --- |
| [`liang1228/UniXNU-violin`](https://github.com/liang1228/UniXNU-violin) | Device port, XNU patches, `ViolinGopProbe`, `ViolinRamOverlay`, Stage-8A build & hook pipeline | `v0.1.0-stage8a-bootable` |
| [`liang1228/UniXNU-xring-o1-common`](https://github.com/liang1228/UniXNU-xring-o1-common) | Shared XRING O1 SoC drivers (`ArmCpu`, `XringUfsRoot`, `XringGpio`, `XringI2c`, `XringDwc3` Slice 1) | `v0.1.0-stage8a-bootable` |
| [`liang1228/uefi-violin`](https://github.com/liang1228/uefi-violin) | EDK2 UEFI firmware (`ViolinPkg`) & `VNPDISK2` FAT32 boot payload builder | `v0.1.0-stage8a-bootable` |

## Building the Bootable Stage-8A Image

1. Prepare the UniXNU Linux `arm64e` cross-toolchain (`/opt/unixnu-out/toolchain-arm64e`), EDK2 `Mu_Basecore`, and your decrypted `ipados-27.0.1-24A446` `OS`/`SystemOS`/`Data` assets under `/opt/unixnu-out/`.
2. Run the self-contained Stage-8A build script (runs host ASan/UBSan TDD, PAC audits, 28-kext `MH_FILESET` prelink + FIPS HMAC seal, and builds both QEMU 4 GiB gate and live 6 GiB `boot_b` images):

```sh
python3 -u scripts/stage8a/build_stage8a.py
```

Optional environment overrides:
- `UNIXNU_DIR`, `UNIXNU_COMMON_DIR`, `UNIXNU_VIOLIN_DIR`, `UNIXNU_UEFI_DIR` (defaults to sibling directories)
- `VIOLIN_UNIQUE_CHIP_ID` (defaults to `0000000000000000`)

3. Prepare Dual-Boot D1 UFS tail (`SHNGROOT v2`) using `scripts/prepare-d1-gpt-split.py` and `scripts/build-d1-shngroot-image.py` (keeps Android `slot a` and GPT `#1..#79` untouched).
4. Flash the generated `violin-stage8a-live-6g-boot_b.img` **only to the inactive `boot_b` slot** (`fastboot flash boot_b ...` + `fastboot set_active b`). To return to Android from the UEFI menu, press **Volume Down + Power** to choose `Restart (Return to Android)`.

## Validation Commands

Run from sibling `../UniXNU`:

```sh
dtc -I dts -O dtb -i ../UniXNU-xring-o1-common/dts -o /tmp/violin.dtb ../UniXNU-violin/dts/violin.dts
python3 scripts/porting-record.py check --device ../UniXNU-violin
./unixnu defconfig violin_defconfig -D ../UniXNU-violin
./unixnu status --json -D ../UniXNU-violin
```
