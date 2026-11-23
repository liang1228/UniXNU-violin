# Violin Device Agent Guide

This repository owns the Xiaomi Pad 7S Pro (`violin`, `O81A`, `XRING O1`) Format 2 board configuration, DTS, defconfigs, porting record (`porting.toml`), and packaging metadata targeting `ipados-27.0.1-24A446` and `macos-27.3-26C5035r` (`arm64e`).

## Read First

- [Porting guide](https://unixnu.com/zh/porting/)
- [Device repository](https://unixnu.com/zh/porting/device-repository)
- [Device tree](https://unixnu.com/zh/porting/device-tree)
- [Component catalog](https://unixnu.com/zh/reference/components) and `UniXNU/components.toml`
- [Porting records](https://unixnu.com/zh/porting/records)
- Sibling `../UniXNU-xring-o1-common/{README.md,AGENTS.md,soc.toml,dts/xring-o1.dtsi}`

## Rules

- Do not remove `example = true` from `board.toml` until real device DRAM bounds, GPT `userdata` LBAs, proprietary firmware hashes, and `uefi-violin` targets are populated and verified.
- Keep `porting.toml` area statuses (`planned`, `implemented`, `host-verified`, `device-verified`, `not-applicable`) strictly supported by real evidence; never treat QEMU loader smoke results as `violin` hardware verification.
- Verify live `violin` `cntfrq_el0`, EL2 (`XHEE`) PAC trapping (`HCR_EL2.APK`/`API`), UART3 vs UART6 console routing, and reserved memory before attempting XNU entry.
- Update affected `porting.toml` `findings` or `evidence` whenever modifying tracked device files and verify with `python3 scripts/porting-record.py check --device ../UniXNU-violin`.
