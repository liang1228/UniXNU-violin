#!/usr/bin/env python3
"""Idempotently install Stage-8A isolated xnu-work hooks (zero edits to source/UniXNU):
  1. bsd/kern/kern_exec.c: post-Data-mount violin_boot_policy_apply() (gated by violin-policy=1)
     ensuring usermanagerd/keybags skeleton dirs exist, writing
     /private/var/db/com.apple.xpc.launchd/disabled.plist (+ disabled.migrated) and
     /private/var/mobile/Library/Preferences/com.apple.springboard.plist (SBDisableAutoDim=true).
  2. bsd/vfs/kpi_vfs.c: owner-dataprotect=1 compatibility for unencrypted writable APFS mounts
     (VNOP_COMPOUND_OPEN, VNOP_CREATE, VNOP_MKDIR, VNOP_COMPOUND_MKDIR, VNOP_SETATTR, VNOP_GETATTR)
     using re-entrancy-safe unixnu.dpclass xattr so APFS never rejects class 1/2/3/6 opens/setattrs.
  3. bsd/kern/bsd_init.c: raise violin_stage5_watchdog cap 180s -> 600s and expand [VIOLIN_HB]
     with RAM overlay, NativeLegacyDisplay, XringBacklight, and owner-dataprotect telemetry.
  4. bsd/kern/kern_exit.c: bounded [VIOLIN_EXIT] logging (with exit_reason_get_string_desc) after proc_unlock.
  5. bsd/kern/kern_sig.c: bounded [VIOLIN_SIG] sender/target/reason tracing for fatal signals to core/UI daemons.
  6. osfmk/arm64/sleh.c: add process name to stage7k_log_user_fault + log EL0 BRK traps in handle_user_breakpoint.
"""
from pathlib import Path
import re

XNU_WORK = Path("/opt/unixnu-out/stage7j-qemu-launchd/tree/.cache/xnu-work")


def patch_kern_exec(xnu_work: Path) -> bool:
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

static void
violin_boot_policy_apply(proc_t p, user_addr_t scratch)
{
	extern volatile uint32_t native_data_persist_state;
	extern volatile uint32_t native_data_persist_header;
	extern volatile uint32_t native_data_write_back;
	kprintf("[VIOLIN_DATA] mounted %s size=%lluMiB ovl_state=%u hdr=%u wb=%u\\n",
	    native_owner_data_device_path,
	    (unsigned long long)(native_owner_data_seed_size >> 20),
	    native_data_persist_state, native_data_persist_header, native_data_write_back);

	uint32_t policy_en = 0;
	if (!PE_parse_boot_argn("violin-policy", &policy_en, sizeof(policy_en)) || policy_en != 1U) {
		return;
	}
	uint32_t lite = 0;
	(void)PE_parse_boot_argn("violin-lite", &lite, sizeof(lite));

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
	int rc_sb = violin_policy_write_file("/private/var/mobile/Library/Preferences/com.apple.springboard.plist",
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
	int rc_pb = violin_policy_write_file("/private/var/mobile/Library/Preferences/com.apple.purplebuddy.plist",
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
	int rc_pbnb = violin_policy_write_file("/private/var/mobile/Library/Preferences/com.apple.purplebuddy.notbackedup.plist",
	    pb_nb_plist, sizeof(pb_nb_plist) - 1, 0600, 501, 501);

	static const char mc_nb_plist[] =
	    "<?xml version=\\"1.0\\" encoding=\\"UTF-8\\"?>\\n"
	    "<!DOCTYPE plist PUBLIC \\"-//Apple//DTD PLIST 1.0//EN\\" "
	    "\\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\\">\\n"
	    "<plist version=\\"1.0\\">\\n<dict>\\n"
	    "\\t<key>LockdownActivationIndicatesCloudConfigurationAvailable</key><false/>\\n"
	    "</dict>\\n</plist>\\n";
	int rc_mc = violin_policy_write_file("/private/var/mobile/Library/Preferences/com.apple.managedconfiguration.notbackedup.plist",
	    mc_nb_plist, sizeof(mc_nb_plist) - 1, 0600, 501, 501);

	kprintf("[VIOLIN_POLICY] lite=%u mkdir=(%d,%d) disabled=%d(%dB) migrated=%d sb=%d pb=(%d,%d,%d)\\n",
	    lite, d1, d2, rc_dis, pos, rc_mig, rc_sb, rc_pb, rc_pbnb, rc_mc);
}
_Static_assert(__builtin_offsetof(struct _posix_spawnattr, psa_sec_flags) == 0xac, "Darwin 26 psa_sec_flags offset");
_Static_assert(__builtin_offsetof(struct _posix_spawnattr, psa_crash_count) == 0xb4, "Darwin 26 psa_crash_count offset");
_Static_assert(__builtin_offsetof(struct _posix_spawnattr, psa_throttle_timeout) == 0xb8, "Darwin 26 psa_throttle_timeout offset");
_Static_assert(__builtin_offsetof(struct _posix_spawnattr, psa_kqworkloop_soft_limit) == 0xbc, "Darwin 26 psa_kqworkloop_soft_limit offset");
_Static_assert(__builtin_offsetof(struct _posix_spawnattr, psa_kqworkloop_hard_limit) == 0xc0, "Darwin 26 psa_kqworkloop_hard_limit offset");
_Static_assert(__builtin_offsetof(struct _posix_spawnattr, psa_conclave_mem_limit) == 0xc4, "Darwin 26 psa_conclave_mem_limit offset");
_Static_assert(__builtin_offsetof(struct _posix_spawnattr, psa_ports) == 0xc8, "Darwin 26 psa_ports offset");
/* VIOLIN_STAGE8A_POLICY_END */"""

    if "/* VIOLIN_STAGE8A_POLICY_START */" in txt:
        new_txt = re.sub(
            r"/\* VIOLIN_STAGE8A_POLICY_START \*/.*?/\* VIOLIN_STAGE8A_POLICY_END \*/",
            lambda _m: policy_func,
            txt,
            count=1,
            flags=re.S,
        )
    else:
        anchor = "static int\nnative_owner_data_prepare(proc_t p, user_addr_t scratch)"
        assert anchor in txt, "Anchor native_owner_data_prepare not found in kern_exec.c"
        new_txt = txt.replace(anchor, policy_func + "\n\n" + anchor, 1)

    call_anchor = "\tif (!error) native_staged_apps_prepare(p, scratch, data_mount);\n"
    call_line = "\tif (!error) violin_boot_policy_apply(p, scratch);\n"
    if call_line not in new_txt:
        assert call_anchor in new_txt, "Call anchor native_staged_apps_prepare not found in kern_exec.c"
        new_txt = new_txt.replace(call_anchor, call_anchor + call_line, 1)

    copyin_old = "\t\t\tif ((error = copyin(px_args.attrp, &px_sa, px_sa_offset)) != 0) {"
    copyin_new = """\t\t\t/* VIOLIN_STAGE8A_COPYIN_START */
\t\t\tvm_size_t violin_sa_copy = (px_args.attr_size < px_sa_offset) ? px_args.attr_size : px_sa_offset;
\t\t\tif ((error = copyin(px_args.attrp, &px_sa, violin_sa_copy)) != 0) {
\t\t\t/* VIOLIN_STAGE8A_COPYIN_END */"""
    if "/* VIOLIN_STAGE8A_COPYIN_START */" in new_txt:
        new_txt = re.sub(
            r"\t\t\t/\* VIOLIN_STAGE8A_COPYIN_START \*/.*?/\* VIOLIN_STAGE8A_COPYIN_END \*/",
            lambda _m: copyin_new,
            new_txt,
            count=1,
            flags=re.S,
        )
    else:
        assert copyin_old in new_txt, "copyin px_sa anchor not found in kern_exec.c"
        new_txt = new_txt.replace(copyin_old, copyin_new, 1)

    changed = new_txt != txt
    if changed:
        p.write_text(new_txt)
    print(f"kern_exec.c: {'UPDATED' if changed else 'UNCHANGED'}")
    return changed


def patch_kpi_vfs(xnu_work: Path) -> bool:
    """Install owner-dataprotect=1 VFS compatibility on unencrypted writable APFS volumes."""
    p = xnu_work / "bsd/vfs/kpi_vfs.c"
    txt = p.read_text()

    helpers = """/* VIOLIN_STAGE8A_DP_START */
#include <pexpert/pexpert.h>
#include <sys/uio_internal.h>
#include <sys/xattr.h>
#include <sys/cprotect.h>

volatile uint64_t violin_dp_compat_ops = 0;

static inline bool
violin_dp_enabled(mount_t mp)
{
	static volatile int dp_arg = -1;
	int val = __atomic_load_n(&dp_arg, __ATOMIC_RELAXED);
	if (__improbable(val < 0)) {
		uint32_t parsed = 0;
		val = (PE_parse_boot_argn("owner-dataprotect", &parsed, sizeof(parsed)) && parsed != 0U) ? 1 : 0;
		__atomic_store_n(&dp_arg, val, __ATOMIC_RELAXED);
	}
	if (!val || mp == NULL) {
		return false;
	}
	if ((mp->mnt_flag & (MNT_CPROTECT | MNT_RDONLY)) != 0) {
		return false;
	}
	return strcmp(mp->mnt_vfsstat.f_fstypename, "apfs") == 0;
}

#define VIOLIN_DP_GUARD_SLOTS 32
static thread_t volatile violin_dp_guard[VIOLIN_DP_GUARD_SLOTS];

static int
violin_dp_guard_enter(void)
{
	thread_t self = current_thread();
	for (int i = 0; i < VIOLIN_DP_GUARD_SLOTS; ++i) {
		if (__atomic_load_n(&violin_dp_guard[i], __ATOMIC_RELAXED) == self) {
			return -1;
		}
	}
	for (int i = 0; i < VIOLIN_DP_GUARD_SLOTS; ++i) {
		thread_t expected = THREAD_NULL;
		if (__atomic_compare_exchange_n(&violin_dp_guard[i], &expected, self,
		    false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
			return i;
		}
	}
	return -1;
}

static void
violin_dp_guard_exit(int slot)
{
	if (slot >= 0 && slot < VIOLIN_DP_GUARD_SLOTS) {
		__atomic_store_n(&violin_dp_guard[slot], THREAD_NULL, __ATOMIC_RELEASE);
	}
}

static void
violin_dp_xattr_set(vnode_t vp, uint32_t cls, vfs_context_t ctx)
{
	if (vp == NULLVP || (vp->v_type != VREG && vp->v_type != VDIR)) {
		return;
	}
	int slot = violin_dp_guard_enter();
	if (slot < 0) {
		return;
	}
	char uio_buf[UIO_SIZEOF(1)];
	uio_t auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_WRITE, uio_buf, sizeof(uio_buf));
	if (auio != NULL) {
		(void)uio_addiov(auio, CAST_USER_ADDR_T(&cls), sizeof(cls));
		(void)VNOP_SETXATTR(vp, "unixnu.dpclass", auio, XATTR_NOSECURITY, ctx);
	}
	violin_dp_guard_exit(slot);
}

static uint32_t
violin_dp_xattr_get(vnode_t vp, vfs_context_t ctx)
{
	uint32_t cls = 4U; /* PROTECTION_CLASS_D */
	if (vp == NULLVP || (vp->v_type != VREG && vp->v_type != VDIR)) {
		return cls;
	}
	int slot = violin_dp_guard_enter();
	if (slot < 0) {
		return cls;
	}
	char uio_buf[UIO_SIZEOF(1)];
	uio_t auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ, uio_buf, sizeof(uio_buf));
	if (auio != NULL) {
		uint32_t got = 0;
		size_t sz = sizeof(got);
		(void)uio_addiov(auio, CAST_USER_ADDR_T(&got), sizeof(got));
		if (VNOP_GETXATTR(vp, "unixnu.dpclass", auio, &sz, XATTR_NOSECURITY, ctx) == 0 &&
		    sz == sizeof(got) && got <= 7U) {
			cls = got;
		}
	}
	violin_dp_guard_exit(slot);
	return cls;
}
/* VIOLIN_STAGE8A_DP_END */"""

    if "/* VIOLIN_STAGE8A_DP_START */" in txt:
        new_txt = re.sub(
            r"/\* VIOLIN_STAGE8A_DP_START \*/.*?/\* VIOLIN_STAGE8A_DP_END \*/",
            lambda _m: helpers,
            txt,
            count=1,
            flags=re.S,
        )
    else:
        inc_anchor = "#include <sys/domain.h>\n"
        assert inc_anchor in txt, "Anchor #include <sys/domain.h> not found in kpi_vfs.c"
        new_txt = txt.replace(inc_anchor, inc_anchor + "\n" + helpers + "\n", 1)

    # 1. VNOP_COMPOUND_OPEN
    co_old = """\t_err = (*dvp->v_op[vnop_compound_open_desc.vdesc_offset])(&a);"""
    co_new = """\t/* VIOLIN_DP_CO_START */
\tbool violin_dp_co = false;
\tuint32_t violin_dp_co_cls = 0;
\tif (vap && VATTR_IS_ACTIVE(vap, va_dataprotect_class) && violin_dp_enabled(dvp->v_mount)) {
\t\tviolin_dp_co = true;
\t\tviolin_dp_co_cls = vap->va_dataprotect_class;
\t\tvap->va_active &= ~VNODE_ATTR_va_dataprotect_class;
\t}
\t_err = (*dvp->v_op[vnop_compound_open_desc.vdesc_offset])(&a);
\tif (violin_dp_co) {
\t\tvap->va_active |= VNODE_ATTR_va_dataprotect_class;
\t\tvap->va_dataprotect_class = violin_dp_co_cls;
\t\tif (_err == 0) {
\t\t\tVATTR_SET_SUPPORTED(vap, va_dataprotect_class);
\t\t\t__atomic_add_fetch(&violin_dp_compat_ops, 1ULL, __ATOMIC_RELAXED);
\t\t\tif (vpp && *vpp) {
\t\t\t\tviolin_dp_xattr_set(*vpp, violin_dp_co_cls, ctx);
\t\t\t}
\t\t}
\t}
\t/* VIOLIN_DP_CO_END */"""
    if "/* VIOLIN_DP_CO_START */" in new_txt:
        new_txt = re.sub(r"\t/\* VIOLIN_DP_CO_START \*/.*?/\* VIOLIN_DP_CO_END \*/", co_new, new_txt, count=1, flags=re.S)
    else:
        assert co_old in new_txt, "VNOP_COMPOUND_OPEN call not found"
        new_txt = new_txt.replace(co_old, co_new, 1)

    # 2. VNOP_CREATE
    cr_old = """\t_err = (*dvp->v_op[vnop_create_desc.vdesc_offset])(&a);"""
    cr_new = """\t/* VIOLIN_DP_CR_START */
\tbool violin_dp_cr = false;
\tuint32_t violin_dp_cr_cls = 0;
\tif (vap && VATTR_IS_ACTIVE(vap, va_dataprotect_class) && violin_dp_enabled(dvp->v_mount)) {
\t\tviolin_dp_cr = true;
\t\tviolin_dp_cr_cls = vap->va_dataprotect_class;
\t\tvap->va_active &= ~VNODE_ATTR_va_dataprotect_class;
\t}
\t_err = (*dvp->v_op[vnop_create_desc.vdesc_offset])(&a);
\tif (violin_dp_cr) {
\t\tvap->va_active |= VNODE_ATTR_va_dataprotect_class;
\t\tvap->va_dataprotect_class = violin_dp_cr_cls;
\t\tif (_err == 0) {
\t\t\tVATTR_SET_SUPPORTED(vap, va_dataprotect_class);
\t\t\t__atomic_add_fetch(&violin_dp_compat_ops, 1ULL, __ATOMIC_RELAXED);
\t\t\tif (vpp && *vpp) {
\t\t\t\tviolin_dp_xattr_set(*vpp, violin_dp_cr_cls, ctx);
\t\t\t}
\t\t}
\t}
\t/* VIOLIN_DP_CR_END */"""
    if "/* VIOLIN_DP_CR_START */" in new_txt:
        new_txt = re.sub(r"\t/\* VIOLIN_DP_CR_START \*/.*?/\* VIOLIN_DP_CR_END \*/", cr_new, new_txt, count=1, flags=re.S)
    else:
        assert cr_old in new_txt, "VNOP_CREATE call not found"
        new_txt = new_txt.replace(cr_old, cr_new, 1)

    # 3. VNOP_MKDIR
    mk_old = """\t_err = (*dvp->v_op[vnop_mkdir_desc.vdesc_offset])(&a);"""
    mk_new = """\t/* VIOLIN_DP_MK_START */
\tbool violin_dp_mk = false;
\tuint32_t violin_dp_mk_cls = 0;
\tif (vap && VATTR_IS_ACTIVE(vap, va_dataprotect_class) && violin_dp_enabled(dvp->v_mount)) {
\t\tviolin_dp_mk = true;
\t\tviolin_dp_mk_cls = vap->va_dataprotect_class;
\t\tvap->va_active &= ~VNODE_ATTR_va_dataprotect_class;
\t}
\t_err = (*dvp->v_op[vnop_mkdir_desc.vdesc_offset])(&a);
\tif (violin_dp_mk) {
\t\tvap->va_active |= VNODE_ATTR_va_dataprotect_class;
\t\tvap->va_dataprotect_class = violin_dp_mk_cls;
\t\tif (_err == 0) {
\t\t\tVATTR_SET_SUPPORTED(vap, va_dataprotect_class);
\t\t\t__atomic_add_fetch(&violin_dp_compat_ops, 1ULL, __ATOMIC_RELAXED);
\t\t\tif (vpp && *vpp) {
\t\t\t\tviolin_dp_xattr_set(*vpp, violin_dp_mk_cls, ctx);
\t\t\t}
\t\t}
\t}
\t/* VIOLIN_DP_MK_END */"""
    if "/* VIOLIN_DP_MK_START */" in new_txt:
        new_txt = re.sub(r"\t/\* VIOLIN_DP_MK_START \*/.*?/\* VIOLIN_DP_MK_END \*/", mk_new, new_txt, count=1, flags=re.S)
    else:
        assert mk_old in new_txt, "VNOP_MKDIR call not found"
        new_txt = new_txt.replace(mk_old, mk_new, 1)

    # 4. VNOP_COMPOUND_MKDIR
    cmk_old = """\t_err = (*dvp->v_op[vnop_compound_mkdir_desc.vdesc_offset])(&a);"""
    cmk_new = """\t/* VIOLIN_DP_CMK_START */
\tbool violin_dp_cmk = false;
\tuint32_t violin_dp_cmk_cls = 0;
\tif (vap && VATTR_IS_ACTIVE(vap, va_dataprotect_class) && violin_dp_enabled(dvp->v_mount)) {
\t\tviolin_dp_cmk = true;
\t\tviolin_dp_cmk_cls = vap->va_dataprotect_class;
\t\tvap->va_active &= ~VNODE_ATTR_va_dataprotect_class;
\t}
\t_err = (*dvp->v_op[vnop_compound_mkdir_desc.vdesc_offset])(&a);
\tif (violin_dp_cmk) {
\t\tvap->va_active |= VNODE_ATTR_va_dataprotect_class;
\t\tvap->va_dataprotect_class = violin_dp_cmk_cls;
\t\tif (_err == 0) {
\t\t\tVATTR_SET_SUPPORTED(vap, va_dataprotect_class);
\t\t\t__atomic_add_fetch(&violin_dp_compat_ops, 1ULL, __ATOMIC_RELAXED);
\t\t\tif (vpp && *vpp) {
\t\t\t\tviolin_dp_xattr_set(*vpp, violin_dp_cmk_cls, ctx);
\t\t\t}
\t\t}
\t}
\t/* VIOLIN_DP_CMK_END */"""
    if "/* VIOLIN_DP_CMK_START */" in new_txt:
        new_txt = re.sub(r"\t/\* VIOLIN_DP_CMK_START \*/.*?/\* VIOLIN_DP_CMK_END \*/", cmk_new, new_txt, count=1, flags=re.S)
    else:
        assert cmk_old in new_txt, "VNOP_COMPOUND_MKDIR call not found"
        new_txt = new_txt.replace(cmk_old, cmk_new, 1)

    # 5. VNOP_SETATTR
    sa_old = """\t_err = (*vp->v_op[vnop_setattr_desc.vdesc_offset])(&a);"""
    sa_new = """\t/* VIOLIN_DP_SA_START */
\tbool violin_dp_sa = false;
\tuint32_t violin_dp_sa_cls = 0;
\tif (vap && VATTR_IS_ACTIVE(vap, va_dataprotect_class) && violin_dp_enabled(vp->v_mount)) {
\t\tviolin_dp_sa = true;
\t\tviolin_dp_sa_cls = vap->va_dataprotect_class;
\t\tvap->va_active &= ~VNODE_ATTR_va_dataprotect_class;
\t}
\tif (violin_dp_sa && vap->va_active == 0) {
\t\t_err = 0;
\t} else {
\t\t_err = (*vp->v_op[vnop_setattr_desc.vdesc_offset])(&a);
\t}
\tif (violin_dp_sa) {
\t\tvap->va_active |= VNODE_ATTR_va_dataprotect_class;
\t\tvap->va_dataprotect_class = violin_dp_sa_cls;
\t\tif (_err == 0) {
\t\t\tVATTR_SET_SUPPORTED(vap, va_dataprotect_class);
\t\t\t__atomic_add_fetch(&violin_dp_compat_ops, 1ULL, __ATOMIC_RELAXED);
\t\t\tviolin_dp_xattr_set(vp, violin_dp_sa_cls, ctx);
\t\t}
\t}
\t/* VIOLIN_DP_SA_END */"""
    if "/* VIOLIN_DP_SA_START */" in new_txt:
        new_txt = re.sub(r"\t/\* VIOLIN_DP_SA_START \*/.*?/\* VIOLIN_DP_SA_END \*/", sa_new, new_txt, count=1, flags=re.S)
    else:
        assert sa_old in new_txt, "VNOP_SETATTR call not found"
        new_txt = new_txt.replace(sa_old, sa_new, 1)

    # 6. VNOP_GETATTR
    ga_old = """\t_err = (*vp->v_op[vnop_getattr_desc.vdesc_offset])(&a);"""
    ga_new = """\t/* VIOLIN_DP_GA_START */
\t_err = (*vp->v_op[vnop_getattr_desc.vdesc_offset])(&a);
\tif (_err == 0 && vap && VATTR_IS_ACTIVE(vap, va_dataprotect_class) &&
\t    !VATTR_IS_SUPPORTED(vap, va_dataprotect_class) && violin_dp_enabled(vp->v_mount)) {
\t\tuint32_t cls = violin_dp_xattr_get(vp, ctx);
\t\tVATTR_RETURN(vap, va_dataprotect_class, cls);
\t\t__atomic_add_fetch(&violin_dp_compat_ops, 1ULL, __ATOMIC_RELAXED);
\t}
\t/* VIOLIN_DP_GA_END */"""
    if "/* VIOLIN_DP_GA_START */" in new_txt:
        new_txt = re.sub(r"\t/\* VIOLIN_DP_GA_START \*/.*?/\* VIOLIN_DP_GA_END \*/", lambda _m: ga_new, new_txt, count=1, flags=re.S)
    else:
        assert ga_old in new_txt, "VNOP_GETATTR call not found"
        new_txt = new_txt.replace(ga_old, ga_new, 1)

    changed = new_txt != txt
    if changed:
        p.write_text(new_txt)
    print(f"kpi_vfs.c: {'UPDATED' if changed else 'UNCHANGED'}")
    return changed


def patch_bsd_init(xnu_work: Path) -> bool:
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
	extern volatile uint32_t armcpu_smp_running;
	extern volatile uint32_t armcpu_core_timer[16];
	extern volatile uint32_t armcpu_core_sgi[16];
	extern int nprocs;
	extern volatile uint64_t xring_ufs_root_verified_blocks;
	extern volatile uint64_t xring_ufs_root_read_requests;
	extern volatile uint64_t xring_ufs_root_read_failures;
	extern volatile uint32_t xring_ufs_root_integrity_failures;
	extern volatile uint64_t xring_ufs_root_write_rejects;
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
		kprintf("[VIOLIN_HB] t=%us/%us nprocs=%d ufs=%lluMiB(rfail=%llu,ifail=%u,wrej=%llu) ovl=%lluMiB(wr=%llu,rej=%llu) dp=%llu disp=(stg=%u,def=%u,cli=%u,val=%u,rej=%u,tx=%u,ret=%u,vs=%u,s0=%u,s7=%u,s11=%u) bl=(lvl=%u,req=%u) wdt=(ccvr=0x%x,k=%u)\\n",
		    elapsed, sec, nprocs,
		    (unsigned long long)(xring_ufs_root_verified_blocks >> 8),
		    (unsigned long long)xring_ufs_root_read_failures,
		    xring_ufs_root_integrity_failures,
		    (unsigned long long)xring_ufs_root_write_rejects,
		    (unsigned long long)(violin_ram_overlay_resident_pages >> 8),
		    (unsigned long long)violin_ram_overlay_writes,
		    (unsigned long long)violin_ram_overlay_cap_rejects,
		    (unsigned long long)violin_dp_compat_ops,
		    violin_legacy_stage, violin_legacy_default_surface_ok,
		    violin_legacy_clients, violin_legacy_validations, violin_legacy_rejected,
		    violin_legacy_transfers, violin_legacy_retirements, violin_legacy_vsync_ticks,
		    native_legacy_swapstat[0], native_legacy_swapstat[7], native_legacy_swapstat[11],
		    xring_backlight_level, xring_backlight_requests,
		    wdt_ccvr, wdt_kicks);
	}
	if (wdt_regs != NULL) {
		wdt_regs[3] = 0x76U;
		__asm__ volatile("dsb sy" ::: "memory");
	}
	kprintf("[XNU_STAGE5_WATCHDOG] TIMEOUT after %us (smp_running=%u timer0=%u sgi0=%u nprocs=%d ufs=%lluMiB ovl=%lluMiB dp=%llu disp_cli=%u disp_ret=%u wdt_k=%u)\\n",
	    sec, armcpu_smp_running, armcpu_core_timer[0], armcpu_core_sgi[0], nprocs,
	    (unsigned long long)(xring_ufs_root_verified_blocks >> 8),
	    (unsigned long long)(violin_ram_overlay_resident_pages >> 8),
	    (unsigned long long)violin_dp_compat_ops,
	    violin_legacy_clients, violin_legacy_retirements, wdt_kicks);
	violin_psci_reset_or_off(1U, "stage5-watchdog");
	thread_terminate(current_thread());
}
/* VIOLIN_STAGE8A_HB_END */"""

    if "/* VIOLIN_STAGE8A_HB_START */" in txt:
        new_txt = re.sub(
            r"/\* VIOLIN_STAGE8A_HB_START \*/.*?/\* VIOLIN_STAGE8A_HB_END \*/",
            lambda _m: new_fn,
            txt,
            count=1,
            flags=re.S,
        )
    else:
        pat = r"static void\nviolin_stage5_watchdog_thread\(void \*arg, __unused wait_result_t wr\)\n\{.*?\n\tthread_terminate\(current_thread\(\)\);\n\}"
        m = re.search(pat, txt, flags=re.S)
        assert m is not None, "violin_stage5_watchdog_thread not found in bsd_init.c"
        new_txt = txt[:m.start()] + new_fn + txt[m.end():]

    changed = new_txt != txt
    if changed:
        p.write_text(new_txt)
    print(f"bsd_init.c: {'UPDATED' if changed else 'UNCHANGED'}")
    return changed


def patch_kern_exit(xnu_work: Path) -> bool:
    p = xnu_work / "bsd/kern/kern_exit.c"
    txt = p.read_text()

    hook = """\t/* VIOLIN_STAGE8A_EXIT_START */
\t{
\t\tstatic volatile uint32_t violin_exit_logged = 0;
\t\tconst char *ename = p->p_name;
\t\tif (ename[0] != '\\0' && violin_exit_logged < 96U &&
\t\t    (strcmp(ename, "launchd") == 0 ||
\t\t     strcmp(ename, "backboardd") == 0 ||
\t\t     strcmp(ename, "SpringBoard") == 0 ||
\t\t     strcmp(ename, "WindowServer") == 0 ||
\t\t     strcmp(ename, "PosterBoard") == 0 ||
\t\t     strcmp(ename, "iconservicesagent") == 0 ||
\t\t     strncmp(ename, "fairplayd", 9) == 0 ||
\t\t     strcmp(ename, "adid") == 0 ||
\t\t     strcmp(ename, "watchdogd") == 0 ||
\t\t     strcmp(ename, "runningboardd") == 0 ||
\t\t     strcmp(ename, "cfprefsd") == 0 ||
\t\t     strcmp(ename, "keybagd") == 0 ||
\t\t     strcmp(ename, "usermanagerd") == 0 ||
\t\t     strcmp(ename, "containermanagerd") == 0 ||
\t\t     strcmp(ename, "securityd") == 0 ||
\t\t     strcmp(ename, "lsd") == 0 ||
\t\t     strcmp(ename, "datamigrator") == 0 ||
\t\t     strcmp(ename, "Setup") == 0 ||
\t\t     strcmp(ename, "installd") == 0 ||
\t\t     strcmp(ename, "logd") == 0)) {
\t\t\textern void kprintf(const char *, ...);
\t\t\tuint32_t seq = __atomic_add_fetch(&violin_exit_logged, 1U, __ATOMIC_RELAXED);
\t\t\tuint32_t ns = (exit_reason != OS_REASON_NULL) ? exit_reason->osr_namespace : 0U;
\t\t\tuint64_t rc = (exit_reason != OS_REASON_NULL) ? exit_reason->osr_code : 0ULL;
\t\t\tconst char *desc = (exit_reason != OS_REASON_NULL) ? exit_reason_get_string_desc(exit_reason) : NULL;
\t\t\tkprintf("[VIOLIN_EXIT #%u] pid=%d ppid=%d name=%s rv=0x%x(sig=%d,code=%d) reason=(ns=%u,code=0x%llx,desc=\\"%.64s\\") jetsam=0x%x\\n",
\t\t\t    seq, proc_pid(p), proc_ppid(p), ename,
\t\t\t    rv, rv & 0x7f, (rv >> 8) & 0xff,
\t\t\t    ns, (unsigned long long)rc, desc ? desc : "", jetsam_flags);
\t\t}
\t}
\t/* VIOLIN_STAGE8A_EXIT_END */"""

    if "/* VIOLIN_STAGE8A_EXIT_START */" in txt:
        new_txt = re.sub(
            r"\t/\* VIOLIN_STAGE8A_EXIT_START \*/.*?/\* VIOLIN_STAGE8A_EXIT_END \*/",
            lambda _m: hook,
            txt,
            count=1,
            flags=re.S,
        )
    else:
        anchor = "\tproc_transend(p, 1);\n\tproc_unlock(p);\n\n\tproc_prepareexit(p, rv, perf_notify);"
        assert anchor in txt, "Anchor proc_prepareexit not found in kern_exit.c"
        repl = "\tproc_transend(p, 1);\n\tproc_unlock(p);\n\n" + hook + "\n\n\tproc_prepareexit(p, rv, perf_notify);"
        new_txt = txt.replace(anchor, repl, 1)

    changed = new_txt != txt
    if changed:
        p.write_text(new_txt)
    print(f"kern_exit.c: {'UPDATED' if changed else 'UNCHANGED'}")
    return changed


def patch_kern_sig(xnu_work: Path) -> bool:
    """Log sender/target/reason whenever SIGKILL/SIGTRAP/SIGABRT/SIGSEGV/SIGBUS targets a watched daemon."""
    p = xnu_work / "bsd/kern/kern_sig.c"
    txt = p.read_text()

    sig_hook = """\t/* VIOLIN_STAGE8A_SIG_START */
\tif (sig_proc != PROC_NULL &&
\t    (signum == SIGKILL || signum == SIGTRAP || signum == SIGABRT || signum == SIGSEGV || signum == SIGBUS)) {
\t\tstatic volatile uint32_t violin_sig_logged = 0;
\t\tconst char *tname = sig_proc->p_name;
\t\tif (tname[0] != '\\0' && violin_sig_logged < 64U &&
\t\t    (strcmp(tname, "SpringBoard") == 0 ||
\t\t     strcmp(tname, "backboardd") == 0 ||
\t\t     strcmp(tname, "lsd") == 0 ||
\t\t     strcmp(tname, "logd") == 0 ||
\t\t     strcmp(tname, "runningboardd") == 0 ||
\t\t     strcmp(tname, "iconservicesagent") == 0 ||
\t\t     strcmp(tname, "PosterBoard") == 0 ||
\t\t     strcmp(tname, "WindowServer") == 0 ||
\t\t     strcmp(tname, "keybagd") == 0 ||
\t\t     strcmp(tname, "usermanagerd") == 0 ||
\t\t     strcmp(tname, "containermanagerd") == 0)) {
\t\t\textern void kprintf(const char *, ...);
\t\t\tuint32_t seq = __atomic_add_fetch(&violin_sig_logged, 1U, __ATOMIC_RELAXED);
\t\t\tproc_t sp = current_proc();
\t\t\tuint32_t ns = (signal_reason != OS_REASON_NULL) ? signal_reason->osr_namespace : 0U;
\t\t\tuint64_t rc = (signal_reason != OS_REASON_NULL) ? signal_reason->osr_code : 0ULL;
\t\t\tconst char *desc = (signal_reason != OS_REASON_NULL) ? exit_reason_get_string_desc(signal_reason) : NULL;
\t\t\tkprintf("[VIOLIN_SIG #%u] from=%d(%s) -> to=%d(%s) sig=%d flv=0x%x cs=0x%x reason=(ns=%u,code=0x%llx,desc=\\"%.48s\\") ra=%p\\n",
\t\t\t    seq, sp ? proc_pid(sp) : -1, (sp && sp->p_name[0]) ? sp->p_name : "?",
\t\t\t    proc_pid(sig_proc), tname, signum, flavor, proc_getcsflags(sig_proc),
\t\t\t    ns, (unsigned long long)rc, desc ? desc : "", __builtin_return_address(0));
\t\t}
\t}
\t/* VIOLIN_STAGE8A_SIG_END */"""

    if "/* VIOLIN_STAGE8A_SIG_START */" in txt:
        new_txt = re.sub(
            r"\t/\* VIOLIN_STAGE8A_SIG_START \*/.*?/\* VIOLIN_STAGE8A_SIG_END \*/",
            lambda _m: sig_hook,
            txt,
            count=1,
            flags=re.S,
        )
    else:
        anchor = "\tif ((sig_task == TASK_NULL) || is_kerneltask(sig_task)) {\n\t\tos_reason_free(signal_reason);\n\t\treturn;\n\t}\n"
        assert anchor in txt, "Anchor sig_task check not found in kern_sig.c"
        new_txt = txt.replace(anchor, anchor + "\n" + sig_hook + "\n", 1)

    changed = new_txt != txt
    if changed:
        p.write_text(new_txt)
    print(f"kern_sig.c: {'UPDATED' if changed else 'UNCHANGED'}")
    return changed


def patch_sleh(xnu_work: Path) -> bool:
    """Enhance stage7k_log_user_fault with process name and hook EL0 BRK traps in handle_user_breakpoint."""
    p = xnu_work / "osfmk/arm64/sleh.c"
    txt = p.read_text()

    # 1. Include proc_name in stage7k_log_user_fault
    old_line = '\tprintf("[STAGE7K_EL0_FAULT] tag=%s pid=%d exc=0x%x c0=0x%llx c1=0x%llx esr=0x%llx far=0x%lx free_pg=%u\\n",\n\t    tag, pid, (unsigned int)exc, (unsigned long long)codes[0], (unsigned long long)codes[1],\n\t    (unsigned long long)esr, (unsigned long)fault_addr, vm_page_free_count);'
    new_line = """\t/* VIOLIN_STAGE8A_FAULT_NAME_START */
\textern void proc_name(int pid, char *buf, int size);
\tchar pname[32] = {0};
\tproc_name(pid, pname, sizeof(pname));
\tprintf("[STAGE7K_EL0_FAULT] tag=%s pid=%d(%s) exc=0x%x c0=0x%llx c1=0x%llx esr=0x%llx far=0x%lx free_pg=%u\\n",
\t    tag, pid, pname[0] ? pname : "?", (unsigned int)exc, (unsigned long long)codes[0], (unsigned long long)codes[1],
\t    (unsigned long long)esr, (unsigned long)fault_addr, vm_page_free_count);
\t/* VIOLIN_STAGE8A_FAULT_NAME_END */"""
    if "/* VIOLIN_STAGE8A_FAULT_NAME_START */" in txt:
        new_txt = re.sub(
            r"\t/\* VIOLIN_STAGE8A_FAULT_NAME_START \*/.*?/\* VIOLIN_STAGE8A_FAULT_NAME_END \*/",
            lambda _m: new_line,
            txt,
            count=1,
            flags=re.S,
        )
    else:
        assert old_line in txt, "stage7k_log_user_fault printf not found in sleh.c"
        new_txt = txt.replace(old_line, new_line, 1)

    # 2. Hook handle_user_breakpoint right before exception_triage(exception, codes, numcodes)
    brk_hook = """\t/* VIOLIN_STAGE8A_BRK_START */
\t{
\t\tstage7k_log_user_fault("user_brk", state, exception, codes, esr, (vm_offset_t)ISS_BRK_COMMENT(esr));
\t}
\t/* VIOLIN_STAGE8A_BRK_END */"""
    if "/* VIOLIN_STAGE8A_BRK_START */" in new_txt:
        new_txt = re.sub(
            r"\t/\* VIOLIN_STAGE8A_BRK_START \*/.*?/\* VIOLIN_STAGE8A_BRK_END \*/",
            lambda _m: brk_hook,
            new_txt,
            count=1,
            flags=re.S,
        )
    else:
        # Locate handle_user_breakpoint's exception_triage call
        m = re.search(
            r"(handle_user_breakpoint\(arm_saved_state_t \*state, uint64_t esr __unused\).*?)(\n\texception_triage\(exception, codes, numcodes\);)",
            new_txt,
            flags=re.S,
        )
        assert m is not None, "handle_user_breakpoint exception_triage not found in sleh.c"
        new_txt = new_txt[:m.start(2)] + "\n" + brk_hook + new_txt[m.start(2):]

    changed = new_txt != txt
    if changed:
        p.write_text(new_txt)
    print(f"sleh.c: {'UPDATED' if changed else 'UNCHANGED'}")
    return changed


def patch_spawn_internal(xnu_work: Path) -> bool:
    """Align struct _posix_spawnattr with Darwin 26 / iPadOS 27.0.1 (24A446) layout (0xc8 bytes).

    Verified directly against 24A446 kernelcache.decompressed posix_spawn (0xfffffe000b24ae7c):
      - copyin size = 0xc8 (200 bytes) at 0xfffffe000b24b0f8 (vs xnu-12377 0xc0)
      - psa_sec_flags widened to uint32_t at offset 0xac (validated against ~0x1f01 at 0xfffffe000b24b144)
      - 4-byte slot at 0xb0 shifts psa_crash_count -> 0xb4 (ldur d0, [x26, #180] at 0xfffffe000b24b7dc)
      - psa_conclave_mem_limit -> 0xc4 (ldr w1, [sp, #500] at 0xfffffe000b24d2e0)
    Without this fix, xnu-12377 misreads 24A446's psa_throttle_timeout (0xb8, typically 10)
    as psa_kqworkloop_hard_limit=10, causing IKOT_TASK_FATAL SIGKILL of every core daemon.
    """
    p = xnu_work / "bsd/sys/spawn_internal.h"
    txt = p.read_text()

    old_block = """\tuint8_t         psa_launch_type;         /* type of launch for launch constraint enforcement */
\tuint16_t        psa_sec_flags;           /* flags for task_sec */"""
    new_block = """\t/* VIOLIN_STAGE8A_SPAWNATTR_START */
\tuint8_t         psa_launch_type;         /* type of launch for launch constraint enforcement */
\tuint32_t        psa_sec_flags;           /* Darwin 26 (24A446) uint32_t at off 0xac */
\tuint32_t        psa_darwin26_reserved;   /* Darwin 26 (24A446) 4B slot at off 0xb0 -> total 0xc8 */
\t/* VIOLIN_STAGE8A_SPAWNATTR_END */"""

    if "/* VIOLIN_STAGE8A_SPAWNATTR_START */" in txt:
        new_txt = re.sub(
            r"\t/\* VIOLIN_STAGE8A_SPAWNATTR_START \*/.*?/\* VIOLIN_STAGE8A_SPAWNATTR_END \*/",
            lambda _m: new_block,
            txt,
            count=1,
            flags=re.S,
        )
    else:
        assert old_block in txt, "psa_launch_type/psa_sec_flags anchor not found in spawn_internal.h"
        new_txt = txt.replace(old_block, new_block, 1)

    changed = new_txt != txt
    if changed:
        p.write_text(new_txt)
    print(f"spawn_internal.h: {'UPDATED' if changed else 'UNCHANGED'}")
    return changed


def patch_kern_proc_kqwl(xnu_work: Path) -> bool:
    """Apply Darwin 26 kqworkloop limit parity (mirrors upstream macos-kqworkloop-limits.patch)."""
    p = xnu_work / "bsd/kern/kern_proc.c"
    txt = p.read_text()

    old_block = """\tfdp->kqwl_dyn_soft_limit = soft_limit;
\tfdp->kqwl_dyn_hard_limit = hard_limit;"""
    new_block = """\t/* VIOLIN_STAGE8A_KQWL_START */
\t/* Darwin 26 (24A446) parity with upstream macos-kqworkloop-limits.patch:
\t * 24A446 release kernel does not enforce kqworkloop limits in posix_spawn, and
\t * xnu-12377 dynamic workloop accounting overcounts against Darwin 26 plist limits. */
\t(void)soft_limit;
\t(void)hard_limit;
\tfdp->kqwl_dyn_soft_limit = KQWL_LIMIT_SENTINEL;
\tfdp->kqwl_dyn_hard_limit = KQWL_LIMIT_SENTINEL;
\t/* VIOLIN_STAGE8A_KQWL_END */"""

    if "/* VIOLIN_STAGE8A_KQWL_START */" in txt:
        new_txt = re.sub(
            r"\t/\* VIOLIN_STAGE8A_KQWL_START \*/.*?/\* VIOLIN_STAGE8A_KQWL_END \*/",
            lambda _m: new_block,
            txt,
            count=1,
            flags=re.S,
        )
    else:
        assert old_block in txt, "kqwl_dyn_soft_limit anchor not found in kern_proc.c"
        new_txt = txt.replace(old_block, new_block, 1)

    changed = new_txt != txt
    if changed:
        p.write_text(new_txt)
    print(f"kern_proc.c: {'UPDATED' if changed else 'UNCHANGED'}")
    return changed


def patch_task_rlim_log(xnu_work: Path) -> bool:
    """Log kprintf telemetry if any CONFIG_PROC_RESOURCE_LIMITS violation ever fires."""
    p = xnu_work / "osfmk/kern/task.c"
    txt = p.read_text()
    new_txt = txt

    specs = [
        (
            "PORTS",
            '\tos_log(OS_LOG_DEFAULT, "process %s[%d] caught allocating too many mach ports. \\\n\t    Num of ports allocated %u; \\n", procname, pid, current_size);',
            '\t/* VIOLIN_RLIM_PORTS_START */\n\tos_log(OS_LOG_DEFAULT, "process %s[%d] caught allocating too many mach ports. \\\n\t    Num of ports allocated %u; \\n", procname, pid, current_size);\n\tkprintf("[VIOLIN_RLIM] kind=ports proc=%s[%d] cur=%u soft=%u hard=%u\\n", procname, pid, current_size, soft_limit, hard_limit);\n\t/* VIOLIN_RLIM_PORTS_END */',
        ),
        (
            "KQWL",
            '\tos_log(OS_LOG_DEFAULT, "process %s[%d] caught allocating too many kqworkloops. \\\n\t    Num of kqworkloops allocated %u; \\n", procname, pid, current_size);',
            '\t/* VIOLIN_RLIM_KQWL_START */\n\tos_log(OS_LOG_DEFAULT, "process %s[%d] caught allocating too many kqworkloops. \\\n\t    Num of kqworkloops allocated %u; \\n", procname, pid, current_size);\n\tkprintf("[VIOLIN_RLIM] kind=kqwl proc=%s[%d] cur=%d soft=%d hard=%d\\n", procname, pid, current_size, soft_limit, hard_limit);\n\t/* VIOLIN_RLIM_KQWL_END */',
        ),
        (
            "FD",
            '\tos_log(OS_LOG_DEFAULT, "process %s[%d] caught allocating too many file descriptors. \\\n\t    Num of fds allocated %u; \\n", procname, pid, current_size);',
            '\t/* VIOLIN_RLIM_FD_START */\n\tos_log(OS_LOG_DEFAULT, "process %s[%d] caught allocating too many file descriptors. \\\n\t    Num of fds allocated %u; \\n", procname, pid, current_size);\n\tkprintf("[VIOLIN_RLIM] kind=fd proc=%s[%d] cur=%d soft=%d hard=%d\\n", procname, pid, current_size, soft_limit, hard_limit);\n\t/* VIOLIN_RLIM_FD_END */',
        ),
    ]
    for tag, old_s, new_s in specs:
        start_m = f"/* VIOLIN_RLIM_{tag}_START */"
        end_m = f"/* VIOLIN_RLIM_{tag}_END */"
        if start_m in new_txt:
            new_txt = re.sub(
                rf"\t/\* VIOLIN_RLIM_{tag}_START \*/.*?/\* VIOLIN_RLIM_{tag}_END \*/",
                lambda _m, rep=new_s: rep,
                new_txt,
                count=1,
                flags=re.S,
            )
        else:
            assert old_s in new_txt, f"task.c anchor {tag} not found"
            new_txt = new_txt.replace(old_s, new_s, 1)

    changed = new_txt != txt
    if changed:
        p.write_text(new_txt)
    print(f"task.c: {'UPDATED' if changed else 'UNCHANGED'}")
    return changed


def main():
    c0 = patch_spawn_internal(XNU_WORK)
    c1 = patch_kern_exec(XNU_WORK)
    c2 = patch_kpi_vfs(XNU_WORK)
    c3 = patch_bsd_init(XNU_WORK)
    c4 = patch_kern_exit(XNU_WORK)
    c5 = patch_kern_sig(XNU_WORK)
    c6 = patch_sleh(XNU_WORK)
    c7 = patch_kern_proc_kqwl(XNU_WORK)
    c8 = patch_task_rlim_log(XNU_WORK)
    print(f"Stage-8A XNU hooks complete (spawn_h={c0} exec={c1} kpi_vfs={c2} bsd_init={c3} exit={c4} sig={c5} sleh={c6} kern_proc={c7} task={c8})")


if __name__ == "__main__":
    main()
