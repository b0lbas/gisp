# gisp — adversarial security audit

Date: 2026-06-26
Method: manual, top-down review against the threat model, plus hand-crafted
malicious containers (not random fuzzing). This complements the earlier
tool-driven work (sanitizers, fuzzing, fault injection, overflow proof).

Files in this directory:

- `report.md`        — this report
- `adversarial.sh`   — the hand-crafted attack scenarios
- `adversarial.log`  — captured output (13/13 passed)
- `byteflip.c`       — 1-byte tamper helper
- `constants.c`      — prints the on-disk layout constants
- `layout.log`       — layout constants vs the manual's spec

---

## 1. Cryptographic-protocol soundness

| Property | Reasoning | Verdict |
|----------|-----------|---------|
| Header authenticated | The 46-byte metadata block (magic, version, opslimit, memlimit, salt, payload length) is passed as AAD to every chunk. Flipping any of those bytes fails decryption (scenarios 1). | **Holds** |
| Stream header authenticated | The 24-byte secretstream header (offset 46) is not in the AAD, but it seeds the pull state, so tampering breaks every chunk's MAC (scenario 2). | **Holds** |
| Per-file key uniqueness | Salt is random per file → Argon2id yields a different key per file; the secretstream header is also random. | **Holds** |
| Chunk reordering | secretstream chains a sequence number into each chunk's MAC, so swapping chunks fails (scenario 3). | **Holds** |
| Cross-file splicing | A's header with B's body fails: different salt → different key, and different stream state (scenario 4). | **Holds** |
| Truncation | Fixed mode checks the exact container size; streamed mode requires a FINAL tag; removing bytes fails (scenario 6). | **Holds** |
| Trailing data | Fixed mode: caught by the size check. Streamed mode: a legitimate final chunk is always a short read, so any appended bytes are pulled into the final chunk and break its MAC; the only "silent-ignore" case (final chunk exactly filling the read buffer) is unreachable without the key. Both rejected (scenario 5). | **Holds** |
| KDF-parameter abuse | opslimit/memlimit are read before authentication but are bounds-checked against operator ceilings first; tampering them only yields a clean auth failure or bounded resource use. | **Holds** |
| Wrong-password oracle | Wrong password and corrupted data take the same path and print the same message (scenario 8); offline guessing is inherent to password-based encryption, not a gisp-specific leak. | **Holds** |

## 2. Trust boundaries / filesystem behavior

| Property | Reasoning | Verdict |
|----------|-----------|---------|
| No write-through symlink at output | Output is created as `out.tmp` with `O_EXCL` (refuses a planted symlink) and `rename()`d into place; rename replaces a symlink at the final path rather than following it. A symlinked output target was left untouched (scenario 7). | **Holds** |
| Restrictive permissions | The temp file is created mode 0600 and rename preserves it, so output is 0600 regardless of umask (named-file mode). | **Holds** |
| Same input/output | `check_same_file` (dev/ino) refuses in==out; the real safety net is the separate `O_EXCL` temp file. | **Holds** |
| No command-execution surface | No `system`/`popen`/`exec`; not setuid; reads the passphrase from `/dev/tty` or an explicit fd/file. | **Holds** |

## 3. libsodium API usage

- Every cryptographic call's return value is checked (`crypto_pwhash`,
  `crypto_secretstream_*_init_pull`, `_pull`, `_push`).
- Correct ordering: init → push/pull per chunk → FINAL tag on the last.
- Buffer sizes verified by hand for all four loops (encrypt/decrypt ×
  fixed/streamed): ciphertext buffers are `CHUNK_SIZE + CRYPTO_ABYTES`,
  plaintext buffers are `CHUNK_SIZE`, and the library never writes more.
- No deprecated or home-grown primitives. **Verdict: correct.**

## 4. Spec vs. implementation

The layout constants printed by `constants.c` match the format table in
`doc/gisp.texi` exactly (see `layout.log`): offsets 0/4/6/14/22/38, 46-byte
AAD block, 24-byte stream header, chunks at 70, 17-byte per-chunk overhead,
65536-byte chunks, and the `0xFFFFFFFFFFFFFFFF` streamed sentinel.
**Verdict: consistent.**

---

## Findings

No vulnerabilities found. All 13 adversarial scenarios behaved correctly.

One **low-severity observation** (robustness, not a security hole):

- The interactive passphrase confirmation compares the two buffers in
  constant time over the full `MAX_PASS_LEN`, relying on `sodium_malloc`
  filling the unused tail of both buffers with the same canary byte. This is
  true for libsodium today, but it is an implicit assumption. Explicitly
  `sodium_memzero`-ing the buffer at the start of `get_password_secure` would
  make the comparison's correctness self-evident. No impact on
  confidentiality or integrity; at worst a future allocator change could cause
  a spurious "passwords do not match".

## Conclusion

From this independent, design-level angle the construction is sound: the
authenticated-encryption framing covers everything security-relevant, the
per-file salt and stream header defeat reordering and splicing, truncation and
trailing data are rejected, the output path resists symlink and permission
attacks, and there is no wrong-password oracle. The implementation matches its
documented format. The single observation above is cosmetic/robustness only.
