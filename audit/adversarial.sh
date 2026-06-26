#!/bin/sh
# adversarial.sh -- hand-crafted attacks against gisp, derived from the threat
# model (not random fuzzing).  Each scenario builds a malicious container and
# asserts gisp rejects it (or, for the symlink case, does not write through).
#
# Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>
# Distributed under the GNU General Public License v3 or later; NO WARRANTY.
#
# Layout constants (see the container-format spec in doc/gisp.texi):
#   header   = 70 bytes   (offset 0)
#   per-chunk overhead (CRYPTO_ABYTES) = 17 bytes
#   CHUNK_SIZE = 65536; so a full chunk on disk = 65553 bytes

set -u
GISP="${GISP:-../src/gisp}"
HDR=70
FULLCHUNK=65553

pass=0; fail=0
ok ()   { echo "  PASS: $1"; pass=$((pass+1)); }
bad ()  { echo "  FAIL: $1"; fail=$((fail+1)); }

# decrypt helper: returns 0 if gisp accepted the container, 1 if it rejected.
dec () { "$GISP" -d "$1" -o "$2" --passphrase-file "$PW" >/dev/null 2>&1; }

work=$(mktemp -d) || exit 99
trap 'rm -rf "$work"' EXIT
PW="$work/pw"; printf 'audit-passphrase-correct' > "$PW"
OUT="$work/out"
rmout () { rm -f "$OUT" "$OUT.tmp"; }

# Build reference containers (cheap KDF for speed).
printf 'plaintext A for the adversarial audit, two chunks worth ......\n' > "$work/pa"
head -c 70000 /dev/zero | tr '\0' 'A' >> "$work/pa"      # > 1 chunk
head -c 70000 /dev/urandom > "$work/pb"
"$GISP" -e "$work/pa" -o "$work/A.gisp" --opslimit 1 --memlimit 8192 --passphrase-file "$PW" 2>/dev/null
"$GISP" -e "$work/pb" -o "$work/B.gisp" --opslimit 1 --memlimit 8192 --passphrase-file "$PW" 2>/dev/null
printf 'short streamed plaintext\n' | "$GISP" -e - -o "$work/S.gisp" --opslimit 1 --memlimit 8192 --passphrase-file "$PW" 2>/dev/null

echo "== 1. AAD coverage: tampering authenticated header fields must fail =="
for spec in "opslimit:6" "memlimit:14" "salt:22" "payload_len:38" "stream_header:50"; do
  name=${spec%%:*}; off=${spec##*:}
  cp "$work/A.gisp" "$work/t.gisp"
  ./byteflip "$work/t.gisp" "$off"
  rmout; if dec "$work/t.gisp" "$OUT"; then bad "tamper $name (offset $off) was ACCEPTED"; else ok "tamper $name (offset $off) rejected"; fi
done

echo "== 2. Secretstream header is implicitly authenticated =="
# already covered by stream_header above; assert one more byte of it
cp "$work/A.gisp" "$work/t.gisp"; ./byteflip "$work/t.gisp" 60
rmout; if dec "$work/t.gisp" "$OUT"; then bad "stream header byte 60 ACCEPTED"; else ok "stream header byte 60 rejected"; fi

echo "== 3. Chunk reordering must fail (sequence authentication) =="
head -c $HDR "$work/A.gisp" > "$work/hdr"
tail -c +$((HDR+1)) "$work/A.gisp" | head -c $FULLCHUNK > "$work/c1"
tail -c +$((HDR+1+FULLCHUNK)) "$work/A.gisp" > "$work/c2"
cat "$work/hdr" "$work/c2" "$work/c1" > "$work/reorder.gisp"
rmout; if dec "$work/reorder.gisp" "$OUT"; then bad "reordered chunks ACCEPTED"; else ok "reordered chunks rejected"; fi

echo "== 4. Cross-file chunk splicing must fail (per-file key/salt) =="
# A's header (salt + stream header) with B's ciphertext body.
head -c $HDR "$work/A.gisp" > "$work/hdrA"
tail -c +$((HDR+1)) "$work/B.gisp" > "$work/bodyB"
cat "$work/hdrA" "$work/bodyB" > "$work/splice.gisp"
rmout; if dec "$work/splice.gisp" "$OUT"; then bad "spliced cross-file chunks ACCEPTED"; else ok "spliced cross-file chunks rejected"; fi

echo "== 5. Trailing data after the stream must fail =="
# fixed-length container + appended bytes
cp "$work/A.gisp" "$work/trail.gisp"; printf 'EXTRA-TRAILING-BYTES' >> "$work/trail.gisp"
rmout; if dec "$work/trail.gisp" "$OUT"; then bad "fixed-mode trailing data ACCEPTED"; else ok "fixed-mode trailing data rejected"; fi
# streamed container + appended bytes
cp "$work/S.gisp" "$work/strail.gisp"; printf 'EXTRA-TRAILING-BYTES' >> "$work/strail.gisp"
rmout; if dec "$work/strail.gisp" "$OUT"; then bad "streamed-mode trailing data ACCEPTED"; else ok "streamed-mode trailing data rejected"; fi

echo "== 6. Truncation must fail =="
sz=$(wc -c < "$work/A.gisp"); head -c $((sz-1)) "$work/A.gisp" > "$work/trunc.gisp"
rmout; if dec "$work/trunc.gisp" "$OUT"; then bad "truncated container ACCEPTED"; else ok "truncated container rejected"; fi

echo "== 7. Symlinked output: rename must replace the link, not write through =="
printf 'SENSITIVE-TARGET-CONTENT' > "$work/target"
ln -s "$work/target" "$work/outlink"
"$GISP" -d "$work/A.gisp" -o "$work/outlink" --passphrase-file "$PW" >/dev/null 2>&1
if [ "$(cat "$work/target")" = "SENSITIVE-TARGET-CONTENT" ]; then
  if [ -L "$work/outlink" ]; then bad "outlink is still a symlink (unexpected)"; else ok "symlink target untouched; link replaced by regular file"; fi
else bad "symlink target was OVERWRITTEN (write-through!)"; fi

echo "== 8. Oracle check: wrong password vs corruption give the same message =="
printf 'audit-passphrase-WRONGWRONG' > "$work/wrongpw"
m_wrong=$("$GISP" -d "$work/A.gisp" -o "$work/o" --passphrase-file "$work/wrongpw" 2>&1 >/dev/null | tail -1)
cp "$work/A.gisp" "$work/corrupt.gisp"; ./byteflip "$work/corrupt.gisp" $((HDR+5))
m_corrupt=$("$GISP" -d "$work/corrupt.gisp" -o "$work/o" --passphrase-file "$PW" 2>&1 >/dev/null | tail -1)
echo "    wrong-password : $m_wrong"
echo "    corrupted-data : $m_corrupt"
if [ "$m_wrong" = "$m_corrupt" ]; then ok "messages identical (no wrong-password oracle)"; else bad "messages differ (oracle leak)"; fi

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
