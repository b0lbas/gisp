#!/bin/sh
# ci/run.sh -- portable build-and-test pipeline for gisp.
#
# Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>
# Distributed under the GNU General Public License v3 or later; NO WARRANTY.
#
# Runs the full gate any CI runner (or a maintainer before a release) should
# pass: a clean bootstrap, build, the test suite, and a from-tarball distcheck.
# A short fuzz smoke run is added when clang/libFuzzer are available, but its
# absence never fails the pipeline -- it is an extra, not a gate.

set -eu
cd "$(dirname "$0")/.."

echo "== bootstrap =="
if [ ! -x ./configure ]; then ./autogen.sh; fi

echo "== configure =="
./configure

echo "== build =="
make

echo "== unit + integration tests =="
make check

echo "== distcheck (out-of-tree build from a fresh tarball) =="
make distcheck

# Deterministic memory-safety gate: rebuild the core plus the unit tests under
# AddressSanitizer and UndefinedBehaviorSanitizer and run them.  -fno-sanitize-
# recover=all turns any finding into a hard failure so CI actually stops.  This
# catches use-after-free / overflow / UB that the time-boxed fuzz smoke might
# not reach.  Uses $CC (gcc and clang both support these).
echo "== sanitizer unit tests (ASan + UBSan) =="
"${CC:-cc}" -fsanitize=address,undefined -fno-sanitize-recover=all -g -O1 \
  -Iinclude -DHAVE_CONFIG_H -I. \
  src/common.c src/crypto.c src/terminal.c tests/test_core.c \
  -o test_san -lsodium
./test_san
rm -f test_san

if command -v clang >/dev/null 2>&1; then
  echo "== fuzz smoke (30s per target) =="
  for t in roundtrip decrypt password; do
    case $t in
      password) srcs="src/common.c src/terminal.c" ;;
      *)        srcs="src/common.c src/crypto.c src/terminal.c" ;;
    esac
    clang -fsanitize=fuzzer,address,undefined -g -O1 -Iinclude -DHAVE_CONFIG_H -I. \
      $srcs "fuzz/fuzz_$t.c" -o "fuzz_$t" -lsodium
    "./fuzz_$t" -max_total_time=30 -print_final_stats=1
    rm -f "fuzz_$t"
  done
else
  echo "== fuzz smoke skipped (clang not found) =="
fi

echo "== CI pipeline OK =="
