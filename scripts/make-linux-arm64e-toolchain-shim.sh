#!/usr/bin/env bash
set -euo pipefail
# Create a lightweight symlink overlay of /opt/unixnu-linux whose clang wrapper
# honors UNIXNU_XNU_ARCH and UNIXNU_IOS_VERSION (arm64e / iOS 27.0) without
# modifying /opt/unixnu-linux or upstream source/UniXNU.

SRC="${1:-/opt/unixnu-linux}"
DST="${2:-/opt/unixnu-out/toolchain-arm64e}"

rm -rf "$DST"
mkdir -p "$DST/CommandLineTools/usr/bin"

for item in "$SRC"/*; do
  base="$(basename "$item")"
  if [[ "$base" != "CommandLineTools" ]]; then
    ln -s "$item" "$DST/$base"
  fi
done

for item in "$SRC/CommandLineTools"/*; do
  base="$(basename "$item")"
  if [[ "$base" != "usr" ]]; then
    ln -s "$item" "$DST/CommandLineTools/$base"
  fi
done

for item in "$SRC/CommandLineTools/usr"/*; do
  base="$(basename "$item")"
  if [[ "$base" != "bin" ]]; then
    ln -s "$item" "$DST/CommandLineTools/usr/$base"
  fi
done

for item in "$SRC/CommandLineTools/usr/bin"/*; do
  base="$(basename "$item")"
  if [[ "$base" != "clang" ]]; then
    ln -s "$item" "$DST/CommandLineTools/usr/bin/$base"
  fi
done

cat > "$DST/CommandLineTools/usr/bin/clang" <<'EOF'
#!/bin/bash
real="${CROSS_CLANG:-/opt/unixnu-linux/llvm/bin/clang}"
drop=(${XNU_CLANG_DROP_FLAGS--mno-implicit-sme})
args=()
for a in "$@"; do
    skip=0
    for d in "${drop[@]}"; do [ "$a" = "$d" ] && skip=1 && break; done
    [ "$skip" = 1 ] || args+=("$a")
done

if [ "${UNIXNU_XNU_ARCH:-}" = "arm64e" ]; then
    triple="arm64e-apple-ios${UNIXNU_IOS_VERSION:-27.0}"
    extra="-fptrauth-function-pointer-type-discrimination -mllvm -disable-atexit-based-global-dtor-lowering"
else
    triple="${DARWIN_TRIPLE:-arm64e-apple-macos26.0}"
    extra="${CROSS_EXTRA_FLAGS--fptrauth-function-pointer-type-discrimination -mllvm -disable-atexit-based-global-dtor-lowering -D__ARM_ARCH_8_2__=1 -D__ARM_ARCH_8_3__=1 -D__ARM_ARCH_8_4__=1 -D__ARM_ARCH_8_5__=1}"
fi

exec "${real}" -target "${triple}" ${extra} "${args[@]}"
EOF
chmod +x "$DST/CommandLineTools/usr/bin/clang"
echo "Created arm64e Linux toolchain overlay at $DST (base: $SRC)"
