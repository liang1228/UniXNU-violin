# UniXNU-violin

UniXNU Format 2 device repository scaffold for **Xiaomi Pad 7S Pro** (`violin` / `O81A` / `XRING O1`), targeting `iPadOS 27` (`ipados-27.0.1-24A446`, primary) and `macOS 27` (`macos-27.3-26C5035r`, via `os_overrides`) on `arm64e`.

## Current Scope

- Shared XRING O1 SoC definitions live in sibling [`UniXNU-xring-o1-common`](../UniXNU-xring-o1-common) and are wired locally through the gitignored `local.toml` (`local.toml.example`).
- Populated from 2026-11-24 live read-only hardware captures on `violin` (`OS4.0.6.0.XOTCNXM` / Linux `6.18.21`): verified raw GPT `userdata` LBAs (`3138056..129089527` @ 4096 B), clean 2 GiB bootstrap window `memory@100000000` inside the 12 GiB high bank, `38.4 MHz` `CNTFRQ_EL0`, and 10/10 QARMA3 PAuth/FPAC (`ID_AA64ISAR2_EL1` `APA3=5`, `GPA3=1`) at EL0.
- `board.toml` retains `example = true` until `proprietary-files.txt` hashes and the pending `uefi-violin` Mu-Silicium repository exist.
- Source baseline: `MiCode/Xiaomi_Kernel_OpenSource` branch `violin-v-oss` (`99a9aff00a2856f065954672660bd0fe0ad0a064`) + live `running-fdt.dtb` (`1c13390e68bee6d7eff86c7a4bd2ae29fd189971df0290cdc855e5c52c9ebbe8`).

## Validation Commands

Run from sibling `../UniXNU`:

```sh
dtc -I dts -O dtb -i ../UniXNU-xring-o1-common/dts -o /tmp/violin.dtb ../UniXNU-violin/dts/violin.dts
python3 scripts/porting-record.py check --device ../UniXNU-violin
./unixnu defconfig violin_defconfig -D ../UniXNU-violin
./unixnu status --json -D ../UniXNU-violin
./unixnu defconfig violin_macos_defconfig -D ../UniXNU-violin --os macos-27
./unixnu status --json -D ../UniXNU-violin --os macos-27
```

## Documentation & Next Steps

- [Device repository guide](https://unixnu.com/zh/porting/device-repository)
- [Porting record guide](https://unixnu.com/zh/porting/records)
- [Device tree guide](https://unixnu.com/zh/porting/device-tree)
- [Bring-up order](https://unixnu.com/zh/porting/bring-up)
- [ARM64e requirements](https://unixnu.com/zh/porting/arm64e)
