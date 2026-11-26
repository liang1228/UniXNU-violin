#!/usr/bin/env python3
"""Idempotently install Stage-8C isolated xnu-work hooks (zero edits to source/UniXNU):
  1. Runs all Stage-8B hooks (which include Stage-8A hooks + BOOTSTRAP_TABLE_SIZE=34 +
     warm-resume-safe ViolinBootPolicy + pre-reboot sync_internal/doSynchronizeCache).
  2. bsd/kern/bsd_init.c: adds [VIOLIN_HB4] and [XNU_STAGE5_WATCHDOG3] telemetry lines
     (strictly <= 13 varargs per kprintf per PRJ-054) reporting:
       - ViolinFastFb (active, frames, last/min/max copy us)
       - ViolinTouch (stage, ready, frames, bad_frames, contacts_seen)
       - ViolinHidInput (stage, edge_install, hid_reports, edge_stats)
"""
import importlib.util
from pathlib import Path
import re

XNU_WORK = Path("/opt/unixnu-out/stage7j-qemu-launchd/tree/.cache/xnu-work")
STAGE8B_HOOKS = Path(__file__).resolve().parent.parent / "stage8b" / "apply_stage8b_xnu_hooks.py"


def patch_bsd_init_stage8c(xnu_work: Path) -> bool:
    p = xnu_work / "bsd/kern/bsd_init.c"
    txt = p.read_text()

    new_fn = """/* VIOLIN_STAGE8A_HB_START */
static void
violin_stage5_watchdog_thread(void *arg, __unused wait_result_t wr)
{
	uint32_t sec = (uint32_t)(uintptr_t)arg;
	if (sec == 0U || sec > 600U) {
		sec = 15U;
	}
	extern void violin_psci_reset_or_off(uint32_t delay_sec, const char *reason);
	extern int sync_internal(void);
	extern void violin_storage_prepare_reboot(void);
	extern volatile uint32_t armcpu_smp_running;
	extern volatile uint32_t armcpu_core_timer[16];
	extern volatile uint32_t armcpu_core_sgi[16];
	extern int nprocs;
	extern int desiredvnodes;
	extern long numvnodes;
	extern unsigned int vm_page_free_count;
	extern volatile uint64_t xring_ufs_root_verified_blocks;
	extern volatile uint64_t xring_ufs_root_read_requests;
	extern volatile uint64_t xring_ufs_root_read_failures;
	extern volatile uint32_t xring_ufs_root_integrity_failures;
	extern volatile uint64_t xring_ufs_root_write_rejects;
	extern volatile uint32_t xring_ufs_data_open_ok;
	extern volatile uint32_t xring_ufs_data_mode_active;
	extern volatile uint64_t xring_ufs_data_reads;
	extern volatile uint64_t xring_ufs_data_writes_fua;
	extern volatile uint64_t xring_ufs_data_writes_cached;
	extern volatile uint64_t xring_ufs_data_syncs;
	extern volatile uint64_t xring_ufs_data_errors;
	extern volatile uint64_t xring_ufs_data_write_rejects;
	extern volatile uint64_t native_data_persist_present;
	extern volatile uint64_t native_data_flushes;
	extern volatile uint64_t violin_ram_overlay_resident_pages;
	extern volatile uint64_t violin_ram_overlay_writes;
	extern volatile uint64_t violin_ram_overlay_cap_rejects;
	extern volatile uint64_t violin_dp_compat_ops;
	extern volatile uint32_t violin_legacy_stage;
	extern volatile uint32_t violin_legacy_default_surface_ok;
	extern volatile uint32_t violin_legacy_clients;
	extern volatile uint32_t violin_legacy_validations;
	extern volatile uint32_t violin_legacy_rejected;
	extern volatile uint32_t violin_legacy_transfers;
	extern volatile uint32_t violin_legacy_retirements;
	extern volatile uint32_t violin_legacy_vsync_ticks;
	extern volatile uint32_t native_legacy_swapstat[16];
	extern volatile uint32_t xring_backlight_level;
	extern volatile uint32_t xring_backlight_requests;
	extern volatile uint32_t violin_fastfb_active;
	extern volatile uint32_t violin_fastfb_frames;
	extern volatile uint64_t violin_legacy_last_copy_us;
	extern volatile uint64_t violin_legacy_copy_min_us;
	extern volatile uint64_t violin_legacy_copy_max_us;
	extern volatile uint32_t violin_touch_stage;
	extern volatile uint32_t violin_touch_ready;
	extern volatile uint32_t violin_touch_frames;
	extern volatile uint32_t violin_touch_bad_frames;
	extern volatile uint32_t violin_touch_contacts_seen;
	extern volatile uint32_t violin_touch_hid_reports;
	extern volatile uint32_t violin_hid_stage;
	extern volatile uint32_t violin_hid_edge_install[3];
	extern volatile uint32_t violin_hid_edge_stats[4];
	extern vm_offset_t ml_io_map(vm_offset_t phys_addr, vm_size_t size);
	uint32_t wdt_kick_en = 0U;
	(void)PE_parse_boot_argn("xring-wdt-kick", &wdt_kick_en, sizeof(wdt_kick_en));
	volatile uint32_t *wdt_regs = NULL;
	uint32_t wdt_kicks = 0U;
	uint32_t wdt_ccvr = 0U;
	if (wdt_kick_en == 1U) {
		vm_offset_t va = ml_io_map((vm_offset_t)0xEC00C000ULL, (vm_size_t)0x1000ULL);
		if (va != 0U) {
			wdt_regs = (volatile uint32_t *)(uintptr_t)va;
			uint32_t cr = wdt_regs[0];
			uint32_t torr = wdt_regs[1];
			uint32_t ccvr0 = wdt_regs[2];
			wdt_regs[3] = 0x76U;
			__asm__ volatile("dsb sy" ::: "memory");
			uint32_t ccvr1 = wdt_regs[2];
			wdt_ccvr = ccvr1;
			wdt_kicks = 1U;
			kprintf("[XRING_WDT] mapped=0xec00c000 cr=0x%x torr=0x%x ccvr=0x%x->0x%x\\n",
			    cr, torr, ccvr0, ccvr1);
		}
	}
	uint32_t elapsed = 0U;
	while (elapsed < sec) {
		uint32_t step = (sec - elapsed > 10U) ? 10U : (sec - elapsed);
		IOSleep(step * 1000U);
		elapsed += step;
		if (wdt_regs != NULL) {
			wdt_ccvr = wdt_regs[2];
			wdt_regs[3] = 0x76U;
			__asm__ volatile("dsb sy" ::: "memory");
			wdt_kicks++;
		}
		kprintf("[VIOLIN_HB] t=%us/%us nprocs=%d vn=%ld/%d free=%uMiB ufs=%lluMiB(rfail=%llu,ifail=%u,wrej=%llu) dp=%llu wdt=(ccvr=0x%x,k=%u)\\n",
		    elapsed, sec, nprocs, numvnodes, desiredvnodes, (vm_page_free_count >> 8),
		    (unsigned long long)(xring_ufs_root_verified_blocks >> 8),
		    (unsigned long long)xring_ufs_root_read_failures,
		    xring_ufs_root_integrity_failures,
		    (unsigned long long)xring_ufs_root_write_rejects,
		    (unsigned long long)violin_dp_compat_ops,
		    wdt_ccvr, wdt_kicks);
		kprintf("[VIOLIN_HB2] sdata=(m=%u,ok=%u,rd=%llu,wf=%llu,wc=%llu,sy=%llu,err=%llu,rej=%llu,pres=%llu,fl=%llu) ovl=%lluMiB(wr=%llu,rej=%llu)\\n",
		    xring_ufs_data_mode_active, xring_ufs_data_open_ok,
		    (unsigned long long)xring_ufs_data_reads,
		    (unsigned long long)xring_ufs_data_writes_fua,
		    (unsigned long long)xring_ufs_data_writes_cached,
		    (unsigned long long)xring_ufs_data_syncs,
		    (unsigned long long)xring_ufs_data_errors,
		    (unsigned long long)xring_ufs_data_write_rejects,
		    (unsigned long long)native_data_persist_present,
		    (unsigned long long)native_data_flushes,
		    (unsigned long long)(violin_ram_overlay_resident_pages >> 8),
		    (unsigned long long)violin_ram_overlay_writes,
		    (unsigned long long)violin_ram_overlay_cap_rejects);
		kprintf("[VIOLIN_HB3] disp=(stg=%u,def=%u,cli=%u,val=%u,rej=%u,tx=%u,ret=%u,vs=%u,s0=%u,s7=%u,s11=%u) bl=(lvl=%u,req=%u)\\n",
		    violin_legacy_stage, violin_legacy_default_surface_ok,
		    violin_legacy_clients, violin_legacy_validations, violin_legacy_rejected,
		    violin_legacy_transfers, violin_legacy_retirements, violin_legacy_vsync_ticks,
		    native_legacy_swapstat[0], native_legacy_swapstat[7], native_legacy_swapstat[11],
		    xring_backlight_level, xring_backlight_requests);
		uint64_t copy_min = (violin_legacy_copy_min_us == UINT64_MAX) ? 0ULL : violin_legacy_copy_min_us;
		kprintf("[VIOLIN_HB4] ffb=(act=%u,fr=%u,last=%llu,min=%llu,max=%llu) tch=(stg=%u,rdy=%u,fr=%u,bad=%u,cnt=%u) hid=(stg=%u,edg=%u,rep=%u)\\n",
		    violin_fastfb_active, violin_fastfb_frames,
		    (unsigned long long)violin_legacy_last_copy_us,
		    (unsigned long long)copy_min,
		    (unsigned long long)violin_legacy_copy_max_us,
		    violin_touch_stage, violin_touch_ready, violin_touch_frames,
		    violin_touch_bad_frames, violin_touch_contacts_seen,
		    violin_hid_stage, violin_hid_edge_install[0], violin_touch_hid_reports);
	}
	if (wdt_regs != NULL) {
		wdt_regs[3] = 0x76U;
		__asm__ volatile("dsb sy" ::: "memory");
		wdt_kicks++;
	}
	/* Clean VFS + SHNGDATA persistent writeback flush before PSCI reset */
	int sync_rc = sync_internal();
	if (wdt_regs != NULL) {
		wdt_regs[3] = 0x76U;
		__asm__ volatile("dsb sy" ::: "memory");
		wdt_kicks++;
	}
	violin_storage_prepare_reboot();
	if (wdt_regs != NULL) {
		wdt_regs[3] = 0x76U;
		__asm__ volatile("dsb sy" ::: "memory");
		wdt_kicks++;
	}
	kprintf("[XNU_STAGE5_WATCHDOG] TIMEOUT after %us (sync_rc=%d smp=%u timer0=%u sgi0=%u nprocs=%d vn=%ld/%d free=%uMiB wdt_k=%u)\\n",
	    sec, sync_rc, armcpu_smp_running, armcpu_core_timer[0], armcpu_core_sgi[0],
	    nprocs, numvnodes, desiredvnodes, (vm_page_free_count >> 8), wdt_kicks);
	kprintf("[XNU_STAGE5_WATCHDOG2] ufs=%lluMiB sdata_pres=%llu sdata_err=%llu sdata_rej=%llu ovl=%lluMiB dp=%llu disp_cli=%u disp_ret=%u\\n",
	    (unsigned long long)(xring_ufs_root_verified_blocks >> 8),
	    (unsigned long long)native_data_persist_present,
	    (unsigned long long)xring_ufs_data_errors,
	    (unsigned long long)xring_ufs_data_write_rejects,
	    (unsigned long long)(violin_ram_overlay_resident_pages >> 8),
	    (unsigned long long)violin_dp_compat_ops,
	    violin_legacy_clients, violin_legacy_retirements);
	uint64_t wd_copy_min = (violin_legacy_copy_min_us == UINT64_MAX) ? 0ULL : violin_legacy_copy_min_us;
	kprintf("[XNU_STAGE5_WATCHDOG3] ffb=(act=%u,fr=%u,min=%llu,max=%llu) tch=(stg=%u,rdy=%u,fr=%u,cnt=%u) hid=(stg=%u,edg=%u,rep=%u,bgn=%u,fe=%u)\\n",
	    violin_fastfb_active, violin_fastfb_frames,
	    (unsigned long long)wd_copy_min, (unsigned long long)violin_legacy_copy_max_us,
	    violin_touch_stage, violin_touch_ready, violin_touch_frames, violin_touch_contacts_seen,
	    violin_hid_stage, violin_hid_edge_install[0], violin_touch_hid_reports,
	    violin_hid_edge_stats[1], violin_hid_edge_stats[2]);
	violin_psci_reset_or_off(1U, "stage5-watchdog");
	thread_terminate(current_thread());
}
/* VIOLIN_STAGE8A_HB_END */"""

    assert "/* VIOLIN_STAGE8A_HB_START */" in txt, "Stage-8A/8B HB block missing in bsd_init.c"
    new_txt = re.sub(
        r"/\* VIOLIN_STAGE8A_HB_START \*/.*?/\* VIOLIN_STAGE8A_HB_END \*/",
        lambda _m: new_fn,
        txt,
        count=1,
        flags=re.S,
    )
    changed = new_txt != txt
    if changed:
        p.write_text(new_txt)
    print(f"bsd_init.c (Stage-8C): {'UPDATED' if changed else 'UNCHANGED'}")
    return changed


def main():
    spec = importlib.util.spec_from_file_location("s8b", STAGE8B_HOOKS)
    s8b = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(s8b)
    s8b.main()
    c_init = patch_bsd_init_stage8c(XNU_WORK)
    print(f"Stage-8C XNU hooks complete (bsd_init={c_init})")


if __name__ == "__main__":
    main()
