#!/usr/bin/env bash
# Fetches a Linux toolchain for building MinE test binaries without root.
# Run inside WSL/Linux:  bash tests/setup-toolchain.sh
# Result: ~/mine-tc/root contains musl-gcc and a static busybox.
set -euo pipefail

TC="$HOME/mine-tc"
mkdir -p "$TC/debs" "$TC/root"
cd "$TC/debs"
apt-get download musl musl-dev musl-tools busybox-static
for d in *.deb; do dpkg-deb -x "$d" "$TC/root"; done

# musl-gcc's specs file hardcodes system paths; point them at our unpacked copy.
orig=$(find "$TC/root" -name musl-gcc.specs | head -1)
spec="$TC/musl-gcc.specs"
sed "s#/usr/lib/x86_64-linux-musl#$TC/root/usr/lib/x86_64-linux-musl#g; s#/usr/include/x86_64-linux-musl#$TC/root/usr/include/x86_64-linux-musl#g" "$orig" > "$spec"
cat > "$TC/musl-gcc" <<EOF
#!/bin/sh
exec gcc "\$@" -specs "$spec"
EOF
chmod +x "$TC/musl-gcc"
echo "musl-gcc: $TC/musl-gcc"
echo "busybox : $(find "$TC/root" -name busybox -type f | head -1)"
