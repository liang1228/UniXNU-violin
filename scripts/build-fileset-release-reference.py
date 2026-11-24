#!/usr/bin/env python3
"""Build a symbol-bearing RELEASE comparison kernel in an isolated output tree."""
import json
import os
import re
import shutil
import hashlib
import argparse
import fnmatch
from pathlib import Path
import subprocess


def file_hash(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def tree_hash(path):
    """Hash inputs by content; follow SDK header-directory links as the compiler does."""
    if not path.is_dir():
        raise FileNotFoundError(path)
    digest = hashlib.sha256()
    for directory, dirs, files in os.walk(path, followlinks=True):
        dirs[:] = sorted(d for d in dirs if d != '.git')
        for name in sorted(files):
            item = Path(directory) / name
            digest.update(str(item.relative_to(path)).encode() + b'\0')
            digest.update(file_hash(item).encode() + b'\0')
    return digest.hexdigest()


def reusable(final, record, inputs):
    try:
        saved = json.loads(record.read_text())
        return saved['inputs'] == inputs and saved['sha256'] == file_hash(final)
    except (OSError, ValueError, KeyError):
        return False


def linked_objects(directory, lto):
    if lto:
        # XNU splits the final link into non-LTO objects and the code generated
        # by its intermediate LTO link. There is no link.filelist in this mode.
        objects = (directory / 'nonltolink.filelist').read_text().splitlines()
        generated = directory / 'justlto.o'
        objects += [str(p) for p in sorted(generated.glob('*.o'))] if generated.is_dir() else [str(generated)]
    else:
        objects = (directory / 'link.filelist').read_text().splitlines()
        objects += [str(directory / name) for name in
                    ('version.o', 'lastkerneldataconst.o', 'lastkernelconstructor.o')
                    if (directory / name).is_file()]
    return [str(Path(name) if Path(name).is_absolute() else directory / name)
            for name in objects if name.strip()]


def require_link_phase(directory, lto, returncode, build_log, log_path):
    """Only repair comparison-link exports after compilation reached the link."""
    errors = re.findall(r'^.*:\d+:\d+: (?:fatal )?error:.*$', build_log, re.M)
    filelist = directory / ('nonltolink.filelist' if lto else 'link.filelist')
    if errors or not filelist.is_file():
        detail = '\n'.join(errors[:5]) or f'Link input list was not generated: {filelist}'
        raise SystemExit(f'RELEASE reference compilation failed ({returncode}); log {log_path}\n{detail}')


def target_define(target):
    if target not in ('ios', 'macosx'):
        raise SystemExit('UNIXNU_XNU_TARGET must be ios or macosx')
    return '-DXNU_TARGET_OS_OSX' if target == 'macosx' else '-DXNU_TARGET_OS_IOS'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', required=True, type=Path, help='prepared XNU build tree of the OS profile')
    parser.add_argument('--lto', action='store_true', help='enable the RELEASE default link-time optimization')
    options = parser.parse_args()
    mode = 'lto' if options.lto else 'snapshot'
    root = options.tree.resolve()
    build_root = root / 'build/xnu/fileset-reference'
    final = build_root / 'mach.release.bcm2837.unstripped.noctf'
    cache_record = final.with_suffix('.json')
    sdk = root / '.cache/fakeroot'
    target = os.environ.get('UNIXNU_XNU_TARGET', 'ios')
    deployment = target_define(target)
    archives = [root/'build/corecrypto-2023/libcorecrypto_kernel_noasm-namespaced.a']
    forced = [root/f'build/{folder}/{name}' for folder,name in (
        ('libpthread-kernel','libpthread_kernel.a'),('armdt-platform','libArmDTPlatform.a'),('armcpu','libArmCpu.a'))]
    linux_lto = (os.uname().sysname == 'Linux' and options.lto)
    clang_env = dict(os.environ)
    if linux_lto:
        clang_env['CROSS_CLANG'] = os.environ.get('UNIXNU_LTO_CLANG', '/usr/bin/clang-21')
    inputs = {
        'mode': mode,
        'target': target,
        'script': file_hash(Path(__file__)),
        'source': tree_hash(root / '.cache/xnu-work'),
        'sdk': tree_hash(sdk),
        'archives': {str(p.relative_to(root)): file_hash(p) for p in archives + forced},
        'versions': {name: os.environ.get(name, default) for name, default in (
            ('UNIXNU_IOS_VERSION', '26.0'), ('UNIXNU_XNU_DARWIN', '25.5.0'),
            ('UNIXNU_XNU_VERSION', '12377.121.6'))},
        'compiler': subprocess.check_output(['xcrun', 'clang', '--version'], text=True, env=clang_env),
        'environment': {name: value for name, value in os.environ.items()
                        if name.startswith(('XNU_', 'RC_', 'CCC_')) or name in ('CC', 'CXX', 'LD')},
    }
    if reusable(final, cache_record, inputs):
        print(f'reference inputs and digest match ({mode}): {final}')
        return
    # Separate workspaces prevent non-LTO objects and stale patched sources from
    # being reused after a mode, source, SDK, archive or compiler change.
    key = hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()
    output = build_root / f'{mode}-{key[:16]}'
    output.mkdir(parents=True, exist_ok=True)
    (output / 'inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    source = output / 'source'
    if not source.exists():
        shutil.copytree(root/'.cache/xnu-work', source, symlinks=True,
                        ignore=shutil.ignore_patterns('.git'))
        # The shared tree currently has this observation hook at file scope. The
        # reference build disables observation hooks; repair only its private copy.
        sleh = source / 'osfmk/arm64/sleh.c'
        text = sleh.read_text()
        misplaced = '\n\tboot_progress_user_breakpoint(state, esr);\n#if __has_feature(ptrauth_calls)'
        if misplaced in text:
            sleh.write_text(text.replace(misplaced, '\n#if __has_feature(ptrauth_calls)', 1))
        if linux_lto:
            # Private non-executing RELEASE reference copy: adapt kalloc type-trait builtins for
            # system clang-21 and run the intermediate LTO codegen step through ld64.lld-21 so
            # ld64-956.6 can link plain Mach-O justlto.o/*.o objects without libLTO.so.
            builtin_shims = (
                '#if !__has_builtin(__builtin_xnu_type_summary)\n'
                '#define __builtin_xnu_type_summary(t) (1UL << KT_GRANULE_DATA)\n'
                '#endif\n'
                '#if !__has_builtin(__builtin_xnu_type_signature)\n'
                '#define __builtin_xnu_type_signature(t) ""\n'
                '#endif\n'
                '#if !__has_builtin(__builtin_xnu_types_compatible)\n'
                '#define __builtin_xnu_types_compatible(a, b) 1\n'
                '#endif\n'
            )
            for rel in ('osfmk/kern/kalloc.h', 'iokit/IOKit/IOLib.h'):
                hp = source / rel
                hp.write_text(builtin_shims + hp.read_text())
            mk_kern = source / 'makedefs/MakeInc.kernel'
            mt = mk_kern.read_text()
            old_lto = '$(LD) $($(addsuffix $(CURRENT_ARCH_CONFIG),ARCH_FLAGS_)) -r nonlto.o -filelist ltolink.filelist $(LDFLAGS_KERNEL_LTO) -Wl,-object_path_lto,$(TARGET)/justlto.o -o $(TARGET)/justlto.tmp.o'
            ios_ver = os.environ.get('UNIXNU_IOS_VERSION', '27.0')
            lld = os.environ.get('UNIXNU_LTO_LLD', '/usr/bin/ld64.lld-21')
            new_lto = (
                f'({lld} -arch arm64e -platform_version ios {ios_ver} {ios_ver} '
                '-dylib -undefined dynamic_lookup -filelist nonltolink.filelist -filelist ltolink.filelist '
                '-mllvm -inline-threshold=100 -object_path_lto $(TARGET)/justlto.o -o $(TARGET)/justlto.tmp.dylib '
                '|| test -s $(TARGET)/justlto.o/0.arm64e.lto.o)'
            )
            assert old_lto in mt, 'Expected PRE_LTO ld -r line in MakeInc.kernel'
            mk_kern.write_text(mt.replace(old_lto, new_lto, 1))
        manifest = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in source.rglob('*') if p.is_file()}
        (output/'source-sha256.json').write_text(json.dumps(manifest,indent=2)+'\n')
    env = dict(clang_env, KERNEL_SDKROOT=str(sdk),
               XNU_AVAILABILITY_PL=str(sdk/'usr/local/libexec/availability.pl'))
    linux_make_args = []
    if os.uname().sysname == 'Linux':
        clt = os.environ.get('CLT_PREFIX', '/opt/unixnu-out/toolchain-arm64e/CommandLineTools/usr')
        env.setdefault('PLATFORM', 'iPhoneOS')
        env.setdefault('HOST_CC', f'{clt}/bin/xnu-host-cc')
        env.setdefault('MIGCOM', f'{clt}/libexec/migcom')
        mem = os.sysconf('SC_PHYS_PAGES') * os.sysconf('SC_PAGE_SIZE')
        cpus = os.cpu_count() or 8
        linux_make_args = [
            'TIGHTBEAMC=tightbeamc-not-supported', 'BUILD_DSYM=0',
            f'MEMORY_SIZE={mem}', f'SYSCTL_HW_PHYSICALCPU={cpus}', f'SYSCTL_HW_LOGICALCPU={cpus}',
            f'LD_KERNEL_LIBS={sdk}/usr/local/lib/kernel/libcc_kext.a',
        ]
    # Match iPad17,3 (T8142, 24A446) BTI+FPAC codegen so fileset_match shape/checked-shape anchors
    # pair against the official 24A446 kernelcache (this comparison reference kernel never executes).
    ptrauth_flags = (
        ' -D__PTRAUTH_INTRINSICS__=1'
        ' -fptrauth-calls -fptrauth-returns -fptrauth-intrinsics -fptrauth-indirect-gotos'
        ' -fptrauth-auth-traps -fptrauth-vtable-pointer-address-discrimination'
        ' -fptrauth-vtable-pointer-type-discrimination -fptrauth-function-pointer-type-discrimination'
    ) if linux_lto else ''
    flags = f'-mcpu=apple-m4 -mbranch-protection=bti{ptrauth_flags} -Wno-reserved-identifier -Wno-pre-c11-compat -Wno-missing-designated-field-initializers -Wno-suggest-override -Wno-unnecessary-virtual-specifier -Wno-suggest-destructor-override -Wno-ms-bitfield-padding -DXNU_NATIVE_PAN=1 -DXNU_SOURCE_CORECRYPTO14=1 -DXNU_BOOT_PROGRESS=0'
    args = ['make','-C',str(source),'build','SDKROOT=iphoneos',
        'ARCH_CONFIGS=ARM64','MACHINE_CONFIGS=BCM2837','KERNEL_CONFIGS=RELEASE',
        'ARCH_STRING_FOR_CURRENT_MACHINE_CONFIG=arm64e','LARGE_MEMORY_DEFINE=-UARM_LARGE_MEMORY',
        'ARM64_LINK_ADDR=0xfffffff007004000','ARM64_PLKSEG_ADDR=0xfffffff004004000',
        f'DEPLOYMENT_TARGET_FLAGS=-miphoneos-version-min={os.environ.get("UNIXNU_IOS_VERSION", "26.0")} {deployment}',
        f'DEPLOYMENT_LINKER_FLAGS=-Wl,-ios_version_min,{os.environ.get("UNIXNU_IOS_VERSION", "26.0")}',
        f'RC_DARWIN_KERNEL_VERSION={os.environ.get("UNIXNU_XNU_DARWIN", "25.5.0")}',
        f'RC_ProjectSourceVersion={os.environ.get("UNIXNU_XNU_VERSION", "12377.121.6")}',
        f'BUILD_LTO={int(options.lto)}','BOUND_CHECKS=0','BUILD_WERROR=0',
        f'MAKEJOBS=-j{os.environ.get("JOBS", "12")}',
        f'XNU_KERNEL_CHAINED_FIXUPS={os.environ.get("XNU_KERNEL_CHAINED_FIXUPS", "1")}',
        f'LDFLAGS_KERNEL_LTO=-miphoneos-version-min={inputs["versions"]["UNIXNU_IOS_VERSION"]} -Wl,-mllvm,-inline-threshold=100',
        f'CFLAGS_EXTRA={flags}',
        'copyio.o_CFLAGS_ADD=-march=armv8.1-a','pcb.o_CFLAGS_ADD=-march=armv8.1-a',
        'LD_KERNEL_ARCHIVES='+' '.join([f'-L{sdk}/usr/local/lib/kernel','-lfirehose_kernel',
                                        *map(str,archives),*(f'-Wl,-force_load,{p}' for p in forced)]),
        'XNU_EXTERNAL_KERNEL_ARCHIVES='+' '.join(map(str,archives+forced)),
        *linux_make_args,
        f'OBJROOT={output}/{mode}-obj',f'SYMROOT={output}/{mode}-sym',f'DSTROOT={output}/{mode}-dst']
    (output/f'{mode}-command.json').write_text(json.dumps(args,indent=2)+'\n')
    with (output/f'{mode}-build.log').open('w') as log:
        result = subprocess.run(args,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT)
    print('RELEASE reference exit',result.returncode,'log',output/f'{mode}-build.log',flush=True)
    # The bring-up patch calls native hooks from the kernel core behind weak_import declarations; on arm64e
    # the authenticated pointer of an undefined weak symbol fails the link. The private copy stubs them: this
    # comparison kernel never runs, the prelink step reads its layout.
    build_log = (output / f'{mode}-build.log').read_text()
    require_link_phase(output / f'{mode}-obj/RELEASE_ARM64_BCM2837', options.lto,
                       result.returncode, build_log, output / f'{mode}-build.log')
    stub_names = sorted(set(re.findall(r'^\s+"(_(?:native_[a-z0-9_]+|boot_log_[a-z0-9_]+|boot_cache_input_capture))"', build_log, re.M)))
    if stub_names:
        (output / 'native-stubs.c').write_text(''.join(f'long {name[1:]};\n' for name in stub_names))   # the linker names carry the leading underscore
        iphoneos = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
        subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-mkernel', '-isysroot', iphoneos, '-c',
                        '-o', str(output / 'native-stubs.o'), str(output / 'native-stubs.c')], check=True)
        at = next(i for i, a in enumerate(args) if a.startswith('LD_KERNEL_ARCHIVES='))
        args[at] += f' -Wl,-force_load,{output}/native-stubs.o'
    # Forced exports the built objects cannot provide: remove them from this private copy and link again
    # (the symbols are absent from the comparison kernel either way; the first link can stop exactly there,
    # and its file list is what names the objects that were built).
    objects = linked_objects(output / f'{mode}-obj/RELEASE_ARM64_BCM2837', options.lto)
    objects += list(map(str, archives + forced))
    names = set()
    for i in range(0, len(objects), 100):
        listed = subprocess.run(['xcrun', 'nm', '-gUj', *objects[i:i + 100]], capture_output=True, text=True, check=True)
        names.update(symbol for symbol in listed.stdout.splitlines() if symbol.startswith('_') and ' ' not in symbol)
    removed = []
    for filename in ('Private.exports', 'Private.arm64.exports'):
        path = output / 'source/config' / filename
        lines = path.read_text().splitlines(keepends=True)
        rejected = {line.strip() for line in lines
                    if line.strip().startswith('_') and ':' not in line and not any(fnmatch.fnmatchcase(n, line.strip()) for n in names)}
        removed.extend(sorted(rejected))
        path.write_text(''.join(line for line in lines if line.strip() not in rejected))
    import json as _json
    record = output / 'omitted-unavailable-forced-exports.json'
    previous = _json.loads(record.read_text()) if record.exists() else []
    record.write_text(_json.dumps(sorted(set(previous + removed)), indent=2) + chr(10))
    print('removed', len(removed), 'unavailable forced exports; linking again')
    with (output / f'{mode}-build.log').open('a') as log:
        result = subprocess.run(args, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
    print('RELEASE reference exit', result.returncode, 'log', output / f'{mode}-build.log', flush=True)
    if result.returncode:
        raise SystemExit(result.returncode)
    built = output / f'{mode}-obj/RELEASE_ARM64_BCM2837/mach.release.bcm2837.unstripped'
    if not built.is_file():
        built = output / f'{mode}-obj/RELEASE_ARM64_BCM2837/mach.release.bcm2837.unstripped.noctf'
    temporary = final.with_suffix('.tmp')
    shutil.copyfile(built, temporary)
    os.replace(temporary, final)
    cache_record.write_text(json.dumps({'inputs': inputs, 'sha256': file_hash(final),
                                  'build': str(output)}, indent=2) + '\n')
    print('reference', final)


if __name__ == '__main__':
    main()
