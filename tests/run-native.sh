#!/usr/bin/env bash
# Sanity check: run every test binary natively on Linux (expected all rc=0).
cd "$(dirname "$0")/bin"
for f in *; do [ "$f" = busybox ] && continue; ./"$f" a b >/dev/null 2>&1; echo "$f rc=$?"; done
rm -f mine_test_file*
