#!/bin/sh
# test_cli.sh -- integration tests for the gisp command-line interface.
#
# Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>
# Distributed under the GNU General Public License v3 or later; NO WARRANTY.
#
# Exercises the pipe/streaming code paths and the new options, which the
# in-process unit tests cannot reach because they drive the library directly.

set -e

GISP="${GISP:-../src/gisp}"
if [ ! -x "$GISP" ]; then
  echo "SKIP: gisp binary not found at $GISP" >&2
  exit 77        # automake's "skipped" exit status
fi

work=$(mktemp -d) || exit 99
trap 'rm -rf "$work"' EXIT

pw="$work/pw"; printf 'correcthorsebatterystaple' > "$pw"
printf 'streaming integration payload, several words long\n' > "$work/plain"

fail () { echo "FAIL: $1" >&2; exit 1; }

# 1. pipe -> pipe round-trip (streamed container).
"$GISP" -e - -o - --passphrase-file "$pw" < "$work/plain" > "$work/v1" 2>/dev/null
"$GISP" -d - -o - --passphrase-file "$pw" < "$work/v1"    > "$work/out1" 2>/dev/null
cmp -s "$work/plain" "$work/out1" || fail "pipe->pipe round-trip"

# 2. file -> stdout (known length), then stdin -> file.
"$GISP" -e "$work/plain" -o - --passphrase-file "$pw" > "$work/v2" 2>/dev/null
"$GISP" -d - -o "$work/out2" --passphrase-file "$pw" < "$work/v2" 2>/dev/null
cmp -s "$work/plain" "$work/out2" || fail "file->stdout interop"

# 3. stdin -> file (streamed), then file -> file.
"$GISP" -e - -o "$work/v3" --passphrase-file "$pw" < "$work/plain" 2>/dev/null
"$GISP" -d "$work/v3" -o "$work/out3" --passphrase-file "$pw" 2>/dev/null
cmp -s "$work/plain" "$work/out3" || fail "stdin->file interop"

# 4. Format check: streamed container stores the sentinel length, a file
#    container stores the real length.
sent=$(od -An -tx1 -j38 -N8 "$work/v3" | tr -d ' \n')
[ "$sent" = "ffffffffffffffff" ] || fail "streamed sentinel length (got $sent)"
real=$(od -An -tx1 -j38 -N8 "$work/v2" | tr -d ' \n')
[ "$real" != "ffffffffffffffff" ] || fail "file container must not use sentinel"

# 5. Empty input through a pipe round-trips to an empty file.
printf '' | "$GISP" -e - -o "$work/ve" --passphrase-file "$pw" 2>/dev/null
"$GISP" -d "$work/ve" -o "$work/oute" --passphrase-file "$pw" 2>/dev/null
[ -f "$work/oute" ] && [ ! -s "$work/oute" ] || fail "empty round-trip"

# 6. Wrong passphrase is rejected.
printf 'totally-the-wrong-passphrase' > "$work/bad"
if "$GISP" -d "$work/v3" -o "$work/x" --passphrase-file "$work/bad" 2>/dev/null; then
  fail "wrong passphrase accepted"
fi

# 7. Passphrase fd 0 must be refused when data also comes from stdin.
if printf data | "$GISP" -e - -o - --passphrase-fd 0 >/dev/null 2>&1; then
  fail "fd 0 / stdin collision not refused"
fi

# 8. A passphrase from a numbered fd works.
"$GISP" -e "$work/plain" -o "$work/v8" --passphrase-fd 3 3<"$pw" 2>/dev/null
"$GISP" -d "$work/v8" -o "$work/out8" --passphrase-fd 3 3<"$pw" 2>/dev/null
cmp -s "$work/plain" "$work/out8" || fail "--passphrase-fd round-trip"

# 9. Minimum password length is enforced, and the weak override relaxes it.
printf 'shortpw' > "$work/shortpw"           # 7 chars, below the default 12
if "$GISP" -e "$work/plain" -o "$work/x" --passphrase-file "$work/shortpw" 2>/dev/null; then
  fail "short passphrase accepted under default minimum"
fi
"$GISP" -e "$work/plain" -o "$work/v9" --min-password-length 4 \
        --allow-weak-password --passphrase-file "$work/shortpw" 2>/dev/null \
  || fail "weak passphrase rejected despite --allow-weak-password"

# 10. An operator ceiling below the container's cost rejects on decrypt.
if "$GISP" -d "$work/v3" -o "$work/x" --max-memlimit 1024 \
           --passphrase-file "$pw" 2>/dev/null; then
  fail "operator memory ceiling not enforced"
fi

echo "All CLI/pipe integration tests passed."
exit 0
