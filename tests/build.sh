#!/usr/bin/env bash
# Builds MinE test binaries. Run inside WSL/Linux from the repo root:
#   bash tests/build.sh
# Needs: gcc (glibc) and tests/setup-toolchain.sh having been run once (musl, busybox).
set -euo pipefail
cd "$(dirname "$0")"
OUT=bin; mkdir -p "$OUT"
MUSL="$HOME/mine-tc/musl-gcc"
CFLAGS="-O2 -g0 -Wall"

gcc -nostdlib -static -o "$OUT/hello_raw" src/hello_raw.S
for t in hello args tls files mem; do
    "$MUSL" $CFLAGS -static -o "$OUT/${t}.musl"       "src/$t.c"
    gcc      $CFLAGS -static -o "$OUT/${t}.glibc-static" "src/$t.c"
    gcc      $CFLAGS         -o "$OUT/${t}.glibc-dyn"    "src/$t.c"
done
cp "$HOME/mine-tc/root/usr/bin/busybox" "$OUT/busybox"

# Minimal rootfs for dynamic binaries: the real glibc loader + libs.
RF=rootfs
mkdir -p "$RF/lib64" "$RF/lib/x86_64-linux-gnu" "$RF/etc" "$RF/tmp" "$RF/bin"
cp -L /lib64/ld-linux-x86-64.so.2 "$RF/lib64/"
for l in libc.so.6 libm.so.6; do cp -L "/lib/x86_64-linux-gnu/$l" "$RF/lib/x86_64-linux-gnu/"; done
cp "$OUT/busybox" "$RF/bin/busybox"
echo "built: $(ls $OUT | wc -l) binaries in tests/$OUT, rootfs in tests/$RF"
