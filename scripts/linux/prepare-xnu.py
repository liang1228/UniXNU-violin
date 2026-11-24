#!/usr/bin/env python3
"""Device-overlaid Linux XNU preparation script for arm64e / iOS 27 builds.

Derived from upstream scripts/linux/prepare-xnu.py, parameterized by
UNIXNU_XNU_ARCH and UNIXNU_IOS_VERSION so libcc_kext.a matches the arm64e
target instead of hardcoding arm64 / iOS 17.0.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
XNU = ROOT / '.cache/xnu-work'
FAKEROOT = ROOT / '.cache/fakeroot'
LLVM_COMMIT = '58c46bae21181fb4240cf964461bea738d96d50e'
LIBC_COMMIT = '899a3b2d52d95d75e05fb286a5e64975ec3de757'   # Libc-1592.100.35
PROFILE_SOURCES = ('InstrProfiling', 'InstrProfilingBuffer', 'InstrProfilingPlatformDarwin', 'InstrProfilingWriter',
                   'InstrProfilingInternal', 'InstrProfilingVersionVar')

ISA_APPLE = '#if defined(__clang__) && ((defined(__apple_build_version__) && __apple_build_version__ > 5010000))\n'
ISA_ANY = '#if defined(__clang__) && (!defined(__apple_build_version__) || __apple_build_version__ > 5010000)\n'
SEEK_OLD = '''\tif (offset != lseek(fd, offset, SEEK_SET)) {
\t\terr = kErrorDiskFull;
\t} else {
\t\terr = kErrorNone;
\t}
'''
SEEK_NEW = '''\tif (offset != lseek(fd, offset, SEEK_SET)) {
\t\tstruct stat st;
\t\t/* Linux lseek() returns 0 on character devices such as the
\t\t * /dev/null that check_all_exports writes to; not an error. */
\t\tif (0 == fstat(fd, &st) && S_ISCHR(st.st_mode)) {
\t\t\treturn kErrorNone;
\t\t}
\t\terr = kErrorDiskFull;
\t} else {
\t\terr = kErrorNone;
\t}
'''


def info(message):
    print(f'[info] {message}', file=sys.stderr)


def rewrite_sources():
    script = XNU / 'bsd/kern/makesyscalls.sh'
    text = script.read_text()
    if '\\(sy_call_t *\\)' in text:
        script.write_text(text.replace('\\(sy_call_t *\\)', '(sy_call_t *)'))
        info('patched bsd/kern/makesyscalls.sh: dropped the \\( escapes mawk keeps')
    for generated in (ROOT / 'build/xnu').rglob('*.c') if (ROOT / 'build/xnu').is_dir() else ():
        if b'\\(sy_call_t' in generated.read_bytes():
            generated.unlink()
            info(f'removed mis-generated {generated}')

    isa = XNU / 'osfmk/arm64/corecrypto/arm64_isa_compatibility.h'
    text = isa.read_text()
    if ISA_APPLE in text:
        isa.write_text(text.replace(ISA_APPLE, ISA_ANY))
        info('patched corecrypto/arm64_isa_compatibility.h: standard vector syntax for non-Apple clang')

    tool = XNU / 'SETUP/kextsymboltool/kextsymboltool.c'
    text = tool.read_text()
    if 'S_ISCHR' not in text:
        if text.count(SEEK_OLD) != 1:
            sys.exit(f'{tool}: seekFile() body not found')
        text = text.replace(SEEK_OLD, SEEK_NEW)
        if '#include <sys/stat.h>' not in text:
            text = text.replace('#include <sys/types.h>', '#include <sys/types.h>\n#include <sys/stat.h>', 1)
        tool.write_text(text)
        info('patched SETUP/kextsymboltool/kextsymboltool.c: lseek() on /dev/null is not a write error')

    (FAKEROOT / 'usr/include').mkdir(parents=True, exist_ok=True)
    shutil.copyfile(HERE / 'TargetConditionals.h', FAKEROOT / 'usr/include/TargetConditionals.h')

    # Upstream LLVM 24 supports 1..3 arguments in __ptrauth(...); Apple Clang's 4th
    # "authenticates-null-values" string argument is not implemented upstream.
    old_auth_null = '#define OS_PTRAUTH_SIGNED_PTR_AUTH_NULL(type) __ptrauth(ptrauth_key_process_independent_data, 1, ptrauth_string_discriminator(type), "authenticates-null-values")'
    new_auth_null = (
        '#if defined(__apple_build_version__)\n'
        '#define OS_PTRAUTH_SIGNED_PTR_AUTH_NULL(type) __ptrauth(ptrauth_key_process_independent_data, 1, ptrauth_string_discriminator(type), "authenticates-null-values")\n'
        '#else\n'
        '#define OS_PTRAUTH_SIGNED_PTR_AUTH_NULL(type) __ptrauth(ptrauth_key_process_independent_data, 1, ptrauth_string_discriminator(type))\n'
        '#endif'
    )
    for rel in ('libkern/os/base.h', 'iokit/IOKit/IOCircularDataQueueImplementation.h'):
        hdr = XNU / rel
        if hdr.is_file():
            htext = hdr.read_text()
            if old_auth_null in htext and '#if defined(__apple_build_version__)' not in htext:
                hdr.write_text(htext.replace(old_auth_null, new_auth_null, 1))
                info(f'patched {rel}: 3-arg __ptrauth fallback for non-Apple clang')
                for stamp in FAKEROOT.glob('.xnu-*-headers'):
                    stamp.unlink(missing_ok=True)


def fetch(directory, url, commit, *paths):
    head = subprocess.run(['git', '-C', directory, 'rev-parse', 'HEAD'], capture_output=True, text=True)
    if head.returncode == 0 and head.stdout.strip() == commit:
        return
    shutil.rmtree(directory, ignore_errors=True)
    for command in (['init', '-q', directory], ['-C', directory, 'sparse-checkout', 'set', '--no-cone', *paths],
                    ['-C', directory, 'fetch', '-q', '--depth', '1', '--filter=blob:none', url, commit],
                    ['-C', directory, 'checkout', '-q', 'FETCH_HEAD']):
        subprocess.run(['git', *map(str, command)], check=True)


def build_cc_kext():
    arch = os.environ.get('UNIXNU_XNU_ARCH', 'arm64')
    ios_ver = os.environ.get('UNIXNU_IOS_VERSION', '17.0')
    triple = f'{arch}-apple-ios{ios_ver}'
    out = FAKEROOT / 'usr/local/lib/kernel/libcc_kext.a'
    stamp = FAKEROOT / 'usr/local/lib/kernel/.libcc_kext.target'
    if out.is_file() and stamp.is_file() and stamp.read_text().strip() == triple:
        return
    src = ROOT / '.cache/linux'
    fetch(src / 'llvm-project', 'https://github.com/llvm/llvm-project', LLVM_COMMIT,
          'compiler-rt/lib/profile', 'compiler-rt/include/profile')
    fetch(src / 'Libc', 'https://github.com/apple-oss-distributions/Libc.git', LIBC_COMMIT, 'include')
    rt = src / 'llvm-project/compiler-rt'
    objects = src / f'cc_kext_{arch}_{ios_ver}'
    objects.mkdir(parents=True, exist_ok=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    for name in PROFILE_SOURCES:
        subprocess.run(['xcrun', 'clang', '-target', triple, '-arch', arch, '-isysroot', FAKEROOT,
                        '-mkernel', '-DKERNEL_USE', '-O3', '-fPIC', '-w',
                        '-I', rt / 'include', '-I', FAKEROOT / 'System/Library/Frameworks/Kernel.framework/Headers',
                        '-idirafter', src / 'Libc/include', '-idirafter', XNU / 'libsyscall/wrappers',
                        '-c', rt / f'lib/profile/{name}.c', '-o', objects / f'{name}.o'], check=True)
    subprocess.run(['xcrun', 'libtool', '-static', '-o', out, *(objects / f'{n}.o' for n in PROFILE_SOURCES)],
                   check=True)
    stamp.write_text(triple + '\n')
    info(f'libcc_kext.a ({triple}): {out}')


if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else ''
    if mode == 'source':
        rewrite_sources()
    elif mode == 'libs':
        build_cc_kext()
    else:
        sys.exit('usage: prepare-xnu.py source|libs')
