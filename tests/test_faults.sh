#!/bin/sh
# test_faults.sh -- drive gisp through its I/O error paths via fault injection.
#
# Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>
# Distributed under the GNU General Public License v3 or later; NO WARRANTY.
#
# Each scenario forces one syscall to fail and asserts gisp fails cleanly
# (non-zero exit, no stale output file left behind).

set -e

GISP="${GISP:-../src/gisp}"
LIB="${FAULTLIB:-./faultlib.so}"
if [ ! -x "$GISP" ] || [ ! -f "$LIB" ]; then
  echo "SKIP: need gisp ($GISP) and faultlib ($LIB)" >&2
  exit 77
fi

work=$(mktemp -d) || exit 99
trap 'rm -rf "$work"' EXIT
pw="$work/pw"; printf 'correcthorsebatterystaple' > "$pw"
printf 'fault injection payload\n' > "$work/plain"
"$GISP" -e "$work/plain" -o "$work/vault" --opslimit 1 --memlimit 8192 \
        --passphrase-file "$pw" 2>/dev/null

fail () { echo "FAIL: $1" >&2; exit 1; }

# run <expect-success?> <out-file> <fault-env...> -- <gisp args...>
run_fault () {
  exp=$1; outf=$2; shift 2
  env=""
  while [ "$1" != "--" ]; do env="$env $1"; shift; done
  shift
  rm -f "$outf" "$outf.tmp"
  if env LD_PRELOAD="$LIB" $env "$GISP" "$@" >/dev/null 2>&1; then rc=0; else rc=1; fi
  if [ "$exp" = ok ] && [ "$rc" -ne 0 ]; then fail "expected success: $*"; fi
  if [ "$exp" = err ] && [ "$rc" -eq 0 ]; then fail "expected failure but succeeded: $*"; fi
  # On a forced failure no stale output must remain.
  if [ "$exp" = err ] && [ -e "$outf" ]; then fail "stale output left: $outf"; fi
}

echo "encrypt: write failure ..."
run_fault err "$work/o1" GISP_FAIL=write -- -e "$work/plain" -o "$work/o1" --opslimit 1 --memlimit 8192 --passphrase-file "$pw"
echo "encrypt: fsync failure ..."
run_fault err "$work/o2" GISP_FAIL=fsync -- -e "$work/plain" -o "$work/o2" --opslimit 1 --memlimit 8192 --passphrase-file "$pw"
echo "encrypt: rename failure ..."
run_fault err "$work/o3" GISP_FAIL=rename -- -e "$work/plain" -o "$work/o3" --opslimit 1 --memlimit 8192 --passphrase-file "$pw"
echo "decrypt: header read failure ..."
run_fault err "$work/o4" GISP_FAIL=read -- -d "$work/vault" -o "$work/o4" --passphrase-file "$pw"
echo "decrypt: payload read failure (skip 2 header reads) ..."
run_fault err "$work/o5" GISP_FAIL=read GISP_FAIL_SKIP=2 -- -d "$work/vault" -o "$work/o5" --passphrase-file "$pw"
echo "decrypt: plaintext write failure ..."
run_fault err "$work/o6" GISP_FAIL=write -- -d "$work/vault" -o "$work/o6" --passphrase-file "$pw"
echo "decrypt: fsync failure ..."
run_fault err "$work/o7" GISP_FAIL=fsync -- -d "$work/vault" -o "$work/o7" --passphrase-file "$pw"
echo "decrypt: rename failure ..."
run_fault err "$work/o8" GISP_FAIL=rename -- -d "$work/vault" -o "$work/o8" --passphrase-file "$pw"

echo "All fault-injection scenarios behaved correctly."
exit 0
