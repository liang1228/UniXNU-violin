#!/usr/bin/env python3
"""Idempotently install Stage-8B isolated xnu-work hooks (zero edits to source/UniXNU):
  1. Runs all Stage-8A hooks (spawn_internal.h, kpi_vfs.c, kern_exit.c, kern_sig.c,
     sleh.c, kern_proc.c, task.c) via apply_stage8a_xnu_hooks.
  2. osfmk/arm/pmap/pmap.h: raise native 4 KiB BOOTSTRAP_TABLE_SIZE from 20 -> 34 pages
     (139,264 bytes) so 8..10 GiB Bank 1 V=P + KVA bootstrap tables never exhaust.
  3. bsd/kern/kern_exec.c: warm-resume-safe violin_boot_policy_apply() that logs
     desiredvnodes/numvnodes/persist-present/GPT status and preserves existing
     user preferences when native_data_persist_state == 2 (Resumed from SHNGDATA).
  4. bsd/kern/bsd_init.c: expand [VIOLIN_HB] with desiredvnodes/numvnodes, free MiB,
     and xring_ufs_data_* telemetry; before stage5 watchdog PSCI reset, kick DW_APB_WDT,
     run sync_internal() + violin_storage_prepare_reboot() so APFS & SHNGDATA bitmaps
     commit durably to UFS 4.1 before reset.
"""
import importlib.util
from pathlib import Path
import re

XNU_WORK = Path("/opt/unixnu-out/stage7j-qemu-launchd/tree/.cache/xnu-work")
STAGE8A_HOOKS = Path(__file__).resolve().parent.parent / "stage8a" / "apply_stage8a_xnu_hooks.py"


def patch_pmap_h(xnu_work: Path) -> bool:
    p = xnu_work / "osfmk/arm/pmap/pmap.h"
    txt = p.read_text()
    old_block = (
        "#elif !defined(APPLE_ARM64_ARCH_FAMILY) && !__ARM_16K_PG__\n"
        "/* Native 4 KiB: two roots plus up to seven L2 pages per 6 GiB mapping.\n"
        " * The physical and virtual bases may each straddle an extra 1 GiB region.\n"
        " */\n"
        "#define BOOTSTRAP_TABLE_SIZE (ARM_PGBYTES * 20)\n"
    )
    new_block = (
        "#elif !defined(APPLE_ARM64_ARCH_FAMILY) && !__ARM_16K_PG__\n"
        "/* Native 4 KiB 4-level TTBR0 + 3-level TTBR1: 3 root/L1 pages plus up to 11 L2\n"
        " * pages each for V=P and KVA on 8..10 GiB windows (25 <= 34, matches ARM_LARGE_MEMORY).\n"
        " */\n"
        "#define BOOTSTRAP_TABLE_SIZE (ARM_PGBYTES * 34)\n"
    )
    if new_block in txt:
        new_txt = txt
    elif old_block in txt:
        new_txt = txt.replace(old_block, new_block, 1)
    else:
        raise AssertionError("Expected BOOTSTRAP_TABLE_SIZE (ARM_PGBYTES * 20) block not found in pmap.h")
    changed = new_txt != txt
    if changed:
        p.write_text(new_txt)
    print(f"pmap.h: {'UPDATED' if changed else 'UNCHANGED'}")
    return changed


def patch_kern_exec_stage8b(xnu_work: Path) -> bool:
    p = xnu_work / "bsd/kern/kern_exec.c"
    txt = p.read_text()

    policy_func = """/* VIOLIN_STAGE8A_POLICY_START */
static int
violin_policy_mkdir(proc_t p, user_addr_t scratch, const char *path, int mode, uid_t uid, gid_t gid)
{
	struct mkdir_args request = {.path = scratch + 0xa00, .mode = mode};
	int32_t result = 0;
	int error = copyout(path, request.path, strlen(path) + 1);
	if (!error) {
		error = mkdir(p, &request, &result);
	}
	if (error && error != EEXIST) {
		return error;
	}
	vnode_t vp = NULLVP;
	error = vnode_lookup(path, VNODE_LOOKUP_NOFOLLOW, &vp, vfs_context_current());
	if (!error) {
		struct vnode_attr va;
		VATTR_INIT(&va);
		VATTR_SET(&va, va_uid, uid);
		VATTR_SET(&va, va_gid, gid);
		(void)vnode_setattr(vp, &va, vfs_context_current());
		vnode_put(vp);
	}
	return error;
}

static bool
violin_policy_file_exists(const char *path)
{
	vnode_t vp = NULLVP;
	if (vnode_lookup(path, VNODE_LOOKUP_NOFOLLOW, &vp, vfs_context_current()) == 0) {
		vnode_put(vp);
		return true;
	}
	return false;
}

static int
violin_policy_write_file(const char *path, const char *data, size_t len, int mode, uid_t uid, gid_t gid)
{
	vfs_context_t ctx = vfs_context_current();
	vnode_t vp = NULLVP;
	int error = vnode_open(path, O_CREAT | O_TRUNC | FWRITE | O_NOFOLLOW, mode, 0, &vp, ctx);
	if (error) {
		return error;
	}
	if (len > 0) {
		int resid = 0;
		error = vn_rdwr(UIO_WRITE, vp, (caddr_t)(uintptr_t)data, (int)len, 0,
		    UIO_SYSSPACE, IO_NOAUTH | IO_UNIT, vfs_context_ucred(ctx), &resid, vfs_context_proc(ctx));
		if (!error && resid != 0) {
			error = EIO;
		}
	}
	if (!error) {
		struct vnode_attr va;
		VATTR_INIT(&va);
		VATTR_SET(&va, va_mode, mode);
		VATTR_SET(&va, va_uid, uid);
		VATTR_SET(&va, va_gid, gid);
		error = vnode_setattr(vp, &va, ctx);
	}
	if (!error) {
		error = VNOP_FSYNC(vp, MNT_WAIT, ctx);
	}
	int close_err = vnode_close(vp, FWRITE, ctx);
	return error ? error : close_err;
}

static int
violin_policy_write_if_missing(bool preserve_existing, const char *path, const char *data, size_t len, int mode, uid_t uid, gid_t gid)
{
	if (preserve_existing && violin_policy_file_exists(path)) {
		return 1; /* preserved existing file from warm SHNGDATA resume */
	}
	return violin_policy_write_file(path, data, len, mode, uid, gid);
}

static void
violin_boot_policy_apply(proc_t p, user_addr_t scratch)
{
	extern volatile uint32_t native_data_persist_state;
	extern volatile uint32_t native_data_persist_header;
	extern volatile uint32_t native_data_write_back;
	extern volatile uint32_t native_data_persist_gpt;
	extern volatile uint32_t native_data_persist_gpt_after;
	extern volatile uint64_t native_data_persist_present;
	extern int desiredvnodes;
	extern long numvnodes;
	kprintf("[VIOLIN_DATA] mounted %s size=%lluMiB ovl_state=%u hdr=%u wb=%u pres=%llu gpt=0x%x/0x%x desiredvnodes=%d numvnodes=%ld\\n",
	    native_owner_data_device_path,
	    (unsigned long long)(native_owner_data_seed_size >> 20),
	    native_data_persist_state, native_data_persist_header, native_data_write_back,
	    (unsigned long long)native_data_persist_present,
	    native_data_persist_gpt, native_data_persist_gpt_after,
	    desiredvnodes, numvnodes);

	uint32_t policy_en = 0;
	if (!PE_parse_boot_argn("violin-policy", &policy_en, sizeof(policy_en)) || policy_en != 1U) {
		return;
	}
	uint32_t lite = 0;
	(void)PE_parse_boot_argn("violin-lite", &lite, sizeof(lite));
	const bool warm_resumed = (native_data_persist_state == 2U);

	/* Ensure keybagd / usermanagerd / containermanagerd skeleton directories exist (non-destructive). */
	static const char *const root_skel_dirs[] = {
		"/private/var/db",
		"/private/var/db/com.apple.xpc.launchd",
		"/private/var/db/dslocal",
		"/private/var/db/dslocal/nodes",
		"/private/var/db/dslocal/nodes/Default",
		"/private/var/db/dslocal/nodes/Default/users",
		"/private/var/db/dslocal/nodes/Default/groups",
		"/private/var/db/dslocal/nodes/Default/config",
		"/private/var/keybags",
		"/private/var/keybags/backup",
		"/private/var/PersonaVolumes",
		"/private/var/containers",
		"/private/var/containers/Data",
		"/private/var/containers/Data/System",
		"/private/var/containers/Data/Application",
		"/private/var/containers/Shared",
		"/private/var/containers/Shared/SystemGroup",
		"/private/var/preboot",
	};
	int d1 = 0, d2 = 0;
	for (size_t i = 0; i < sizeof(root_skel_dirs) / sizeof(root_skel_dirs[0]); ++i) {
		int rc = violin_policy_mkdir(p, scratch, root_skel_dirs[i], 0755, 0, 0);
		if (i == 0) d1 = rc;
		if (i == 1) d2 = rc;
	}

	static char disabled_buf[4096];
	int pos = snprintf(disabled_buf, sizeof(disabled_buf),
	    "<?xml version=\\"1.0\\" encoding=\\"UTF-8\\"?>\\n"
	    "<!DOCTYPE plist PUBLIC \\"-//Apple//DTD PLIST 1.0//EN\\" "
	    "\\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\\">\\n"
	    "<plist version=\\"1.0\\">\\n<dict>\\n"
	    "\\t<key>com.apple.watchdogd</key><true/>\\n"
	    "\\t<key>com.apple.fairplayd.A2</key><true/>\\n"
	    "\\t<key>com.apple.fairplayd.H2</key><true/>\\n"
	    "\\t<key>com.apple.adid</key><true/>\\n");
	if (lite >= 1U && pos > 0 && (size_t)pos < sizeof(disabled_buf)) {
		static const char *const lite_jobs[] = {
			"com.apple.bluetoothd",
			"com.apple.wifid",
			"com.apple.cameracaptured",
			"com.apple.locationd",
			"com.apple.identityservicesd",
			"com.apple.cloudd",
			"com.apple.photoanalysisd",
			"com.apple.medialibraryd",
			"com.apple.coreduetd",
			"com.apple.duetexpertd",
			"com.apple.suggestd",
			"com.apple.triald",
			"com.apple.biomesyncd",
			"com.apple.rapportd",
			"com.apple.sharingd",
			"com.apple.intelligenceplatformd",
			"com.apple.IntelligencePlatformComputeService",
			"com.apple.softwareupdateservicesd",
			"com.apple.fileindexerd",
			"com.apple.siriactionsd",
			"com.apple.parsec-fbf",
			"com.apple.aonsensed",
		};
		for (size_t i = 0; i < sizeof(lite_jobs) / sizeof(lite_jobs[0]); ++i) {
			int w = snprintf(disabled_buf + pos, sizeof(disabled_buf) - (size_t)pos,
			    "\\t<key>%s</key><true/>\\n", lite_jobs[i]);
			if (w > 0 && (size_t)(pos + w) < sizeof(disabled_buf)) {
				pos += w;
			}
		}
	}
	if (lite >= 2U && pos > 0 && (size_t)pos < sizeof(disabled_buf)) {
		int w = snprintf(disabled_buf + pos, sizeof(disabled_buf) - (size_t)pos,
		    "\\t<key>com.apple.iconservices.iconservicesagent</key><true/>\\n"
		    "\\t<key>com.apple.iconservices.iconservicesd</key><true/>\\n");
		if (w > 0 && (size_t)(pos + w) < sizeof(disabled_buf)) {
			pos += w;
		}
	}
	if (pos > 0 && (size_t)pos < sizeof(disabled_buf)) {
		int w = snprintf(disabled_buf + pos, sizeof(disabled_buf) - (size_t)pos,
		    "</dict>\\n</plist>\\n");
		if (w > 0 && (size_t)(pos + w) < sizeof(disabled_buf)) {
			pos += w;
		}
	}
	int rc_dis = violin_policy_write_file("/private/var/db/com.apple.xpc.launchd/disabled.plist",
	    disabled_buf, (size_t)pos, 0644, 0, 0);
	int rc_mig = violin_policy_write_file("/private/var/db/com.apple.xpc.launchd/disabled.migrated",
	    "", 0, 0644, 0, 0);

	static const char *const mobile_skel_dirs[] = {
		"/private/var/mobile",
		"/private/var/mobile/Library",
		"/private/var/mobile/Library/Preferences",
		"/private/var/mobile/Library/Caches",
		"/private/var/mobile/Library/Logs",
		"/private/var/mobile/Containers",
		"/private/var/mobile/Documents",
		"/private/var/mobile/Media",
		"/private/var/mobile/tmp",
	};
	for (size_t i = 0; i < sizeof(mobile_skel_dirs) / sizeof(mobile_skel_dirs[0]); ++i) {
		(void)violin_policy_mkdir(p, scratch, mobile_skel_dirs[i], 0755, 501, 501);
	}

	static const char sb_plist[] =
	    "<?xml version=\\"1.0\\" encoding=\\"UTF-8\\"?>\\n"
	    "<!DOCTYPE plist PUBLIC \\"-//Apple//DTD PLIST 1.0//EN\\" "
	    "\\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\\">\\n"
	    "<plist version=\\"1.0\\">\\n<dict>\\n"
	    "\\t<key>BKNoWatchdogs</key><true/>\\n"
	    "\\t<key>FBLaunchWatchdogExceptions</key><dict><key>com.apple.purplebuddy</key><real>100</real></dict>\\n"
	    "\\t<key>MCForceShowCloudConfigurationUI</key><false/>\\n"
	    "\\t<key>SBDisableAutoDim</key><true/>\\n"
	    "\\t<key>SBDontDimOrLockOnAC</key><true/>\\n"
	    "\\t<key>SBDisableIdleSleep</key><true/>\\n"
	    "</dict>\\n</plist>\\n";
	int rc_sb = violin_policy_write_if_missing(warm_resumed,
	    "/private/var/mobile/Library/Preferences/com.apple.springboard.plist",
	    sb_plist, sizeof(sb_plist) - 1, 0600, 501, 501);

	static const char pb_plist[] =
	    "<?xml version=\\"1.0\\" encoding=\\"UTF-8\\"?>\\n"
	    "<!DOCTYPE plist PUBLIC \\"-//Apple//DTD PLIST 1.0//EN\\" "
	    "\\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\\">\\n"
	    "<plist version=\\"1.0\\">\\n<dict>\\n"
	    "\\t<key>SetupDone</key><true/>\\n"
	    "\\t<key>SetupFinishedAllSteps</key><true/>\\n"
	    "\\t<key>SetupVersion</key><integer>11</integer>\\n"
	    "\\t<key>daemonizeNeedsToRun</key><false/>\\n"
	    "</dict>\\n</plist>\\n";
	int rc_pb = violin_policy_write_if_missing(warm_resumed,
	    "/private/var/mobile/Library/Preferences/com.apple.purplebuddy.plist",
	    pb_plist, sizeof(pb_plist) - 1, 0600, 501, 501);

	static const char pb_nb_plist[] =
	    "<?xml version=\\"1.0\\" encoding=\\"UTF-8\\"?>\\n"
	    "<!DOCTYPE plist PUBLIC \\"-//Apple//DTD PLIST 1.0//EN\\" "
	    "\\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\\">\\n"
	    "<plist version=\\"1.0\\">\\n<dict>\\n"
	    "\\t<key>ShouldRunDiagnosticsMiniBuddy</key><false/>\\n"
	    "\\t<key>ShouldRunHSA2MiniBuddy</key><false/>\\n"
	    "\\t<key>ShouldRunKeychainSyncMiniBuddy</key><false/>\\n"
	    "\\t<key>ShouldRunMesaMiniBuddy</key><false/>\\n"
	    "\\t<key>ShouldRunPaymentMiniBuddy</key><false/>\\n"
	    "\\t<key>ShouldRunStandardMiniBuddy</key><false/>\\n"
	    "\\t<key>SilentICDPUpgrade</key><false/>\\n"
	    "</dict>\\n</plist>\\n";
	int rc_pbnb = violin_policy_write_if_missing(warm_resumed,
	    "/private/var/mobile/Library/Preferences/com.apple.purplebuddy.notbackedup.plist",
	    pb_nb_plist, sizeof(pb_nb_plist) - 1, 0600, 501, 501);

	static const char mc_nb_plist[] =
	    "<?xml version=\\"1.0\\" encoding=\\"UTF-8\\"?>\\n"
	    "<!DOCTYPE plist PUBLIC \\"-//Apple//DTD PLIST 1.0//EN\\" "
	    "\\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\\">\\n"
	    "<plist version=\\"1.0\\">\\n<dict>\\n"
	    "\\t<key>LockdownActivationIndicatesCloudConfigurationAvailable</key><false/>\\n"
	    "</dict>\\n</plist>\\n";
	int rc_mc = violin_policy_write_if_missing(warm_resumed,
	    "/private/var/mobile/Library/Preferences/com.apple.managedconfiguration.notbackedup.plist",
	    mc_nb_plist, sizeof(mc_nb_plist) - 1, 0600, 501, 501);

	kprintf("[VIOLIN_POLICY] lite=%u resumed=%u mkdir=(%d,%d) disabled=%d(%dB) migrated=%d sb=%d pb=(%d,%d,%d)\\n",
	    lite, warm_resumed ? 1U : 0U, d1, d2, rc_dis, pos, rc_mig, rc_sb, rc_pb, rc_pbnb, rc_mc);
}
_Static_assert(__builtin_offsetof(struct _posix_spawnattr, psa_sec_flags) == 0xac, "Darwin 26 psa_sec_flags offset");
_Static_assert(__builtin_offsetof(struct _posix_spawnattr, psa_crash_count) == 0xb4, "Darwin 26 psa_crash_count offset");
_Static_assert(__builtin_offsetof(struct _posix_spawnattr, psa_throttle_timeout) == 0xb8, "Darwin 26 psa_throttle_timeout offset");
_Static_assert(__builtin_offsetof(struct _posix_spawnattr, psa_kqworkloop_soft_limit) == 0xbc, "Darwin 26 psa_kqworkloop_soft_limit offset");
_Static_assert(__builtin_offsetof(struct _posix_spawnattr, psa_kqworkloop_hard_limit) == 0xc0, "Darwin 26 psa_kqworkloop_hard_limit offset");
_Static_assert(__builtin_offsetof(struct _posix_spawnattr, psa_conclave_mem_limit) == 0xc4, "Darwin 26 psa_conclave_mem_limit offset");
_Static_assert(__builtin_offsetof(struct _posix_spawnattr, psa_ports) == 0xc8, "Darwin 26 psa_ports offset");
/* VIOLIN_STAGE8A_POLICY_END */"""

    assert "/* VIOLIN_STAGE8A_POLICY_START */" in txt, "Stage-8A policy block missing in kern_exec.c"
    new_txt = re.sub(
        r"/\* VIOLIN_STAGE8A_POLICY_START \*/.*?/\* VIOLIN_STAGE8A_POLICY_END \*/",
        lambda _m: policy_func,
        txt,
        count=1,
        flags=re.S,
    )
    changed = new_txt != txt
    if changed:
        p.write_text(new_txt)
    print(f"kern_exec.c (Stage-8B): {'UPDATED' if changed else 'UNCHANGED'}")
    return changed


def patch_bsd_init_stage8b(xnu_work: Path) -> bool:
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
	violin_psci_reset_or_off(1U, "stage5-watchdog");
	thread_terminate(current_thread());
}
/* VIOLIN_STAGE8A_HB_END */"""

    assert "/* VIOLIN_STAGE8A_HB_START */" in txt, "Stage-8A HB block missing in bsd_init.c"
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
    print(f"bsd_init.c (Stage-8B): {'UPDATED' if changed else 'UNCHANGED'}")
    return changed


def main():
    spec = importlib.util.spec_from_file_location("s8a", STAGE8A_HOOKS)
    s8a = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(s8a)

    # Run all baseline Stage-8A hooks first (idempotent)
    s8a.main()

    # Apply Stage-8B upgrades on top
    c_pmap = patch_pmap_h(XNU_WORK)
    c_exec = patch_kern_exec_stage8b(XNU_WORK)
    c_init = patch_bsd_init_stage8b(XNU_WORK)
    print(f"Stage-8B XNU hooks complete (pmap={c_pmap} exec={c_exec} bsd_init={c_init})")


if __name__ == "__main__":
    main()
