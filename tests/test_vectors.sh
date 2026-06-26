#!/bin/sh
# test_vectors.sh -- known-answer / format-stability tests.
#
# Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>
# Distributed under the GNU General Public License v3 or later; NO WARRANTY.
#
# Decrypts pre-built containers stored under vectors/ and checks they still
# yield the known plaintext.  Because the container bytes are pinned in the
# repository, any accidental change to the on-disk layout, field offsets, or
# endianness makes these tests fail.

set -e

GISP="${GISP:-../src/gisp}"
here=$(dirname "$0")
VEC="$here/vectors"

if [ ! -x "$GISP" ] || [ ! -d "$VEC" ]; then
  echo "SKIP: need gisp ($GISP) and vectors ($VEC)" >&2
  exit 77
fi

work=$(mktemp -d) || exit 99
trap 'rm -rf "$work"' EXIT
fail () { echo "FAIL: $1" >&2; exit 1; }

# 1. Fixed-length and streamed vectors must decrypt to the stored plaintext.
for v in v1_fixed v1_streamed; do
  "$GISP" -d "$VEC/$v.gisp" -o "$work/out" --passphrase-file "$VEC/passphrase" 2>/dev/null \
    || fail "$v failed to decrypt"
  cmp -s "$work/out" "$VEC/plaintext" || fail "$v plaintext mismatch (format drift?)"
  rm -f "$work/out"
done

# 2. The truncated container must be rejected (no plaintext produced).
if "$GISP" -d "$VEC/v1_truncated.gisp" -o "$work/out" \
           --passphrase-file "$VEC/passphrase" 2>/dev/null; then
  fail "truncated container was accepted"
fi
[ ! -e "$work/out" ] || fail "truncated decrypt left output behind"

# 3. A wrong passphrase must be rejected.
printf 'definitely-the-wrong-passphrase' > "$work/bad"
if "$GISP" -d "$VEC/v1_fixed.gisp" -o "$work/out" \
           --passphrase-file "$work/bad" 2>/dev/null; then
  fail "wrong passphrase accepted on vector"
fi

echo "All known-answer / format-stability tests passed."
exit 0
