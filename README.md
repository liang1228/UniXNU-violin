# UniXNU-violin

UniXNU Format 2 device repository scaffold for **Xiaomi Pad 7S Pro** (`violin` / `O81A` / `XRING O1`), targeting `iPadOS 27` (`ipados-27.0.1-24A446`, primary) and `macOS 27` (`macos-27.3-26C5035r`, via `os_overrides`) on `arm64e`.

## Current Scope

- Shared XRING O1 SoC definitions live in sibling [`UniXNU-xring-o1-common`](../UniXNU-xring-o1-common) and are wired locally through the gitignored `local.toml` (`local.toml.example`).
- `board.toml` currently retains `example = true` and `0` / `REQUIRED_*` placeholders for uncaptured device GPT `userdata` LBAs, live DRAM banks, firmware blobs (`proprietary-files.txt`), and the pending `uefi-violin` Mu-Silicium repository.
- Hardware source baseline: `MiCode/Xiaomi_Kernel_OpenSource` branch `violin-v-oss` (`99a9aff00a2856f065954672660bd0fe0ad0a064`).

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
