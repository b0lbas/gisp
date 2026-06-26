# Security Policy

## Reporting a vulnerability

Please report security issues privately to **cmrtumilovic@gmail.com**.
Do not open a public issue for an unfixed vulnerability. You will receive an
acknowledgement, and a fix and disclosure will be coordinated with you.

If you wish to encrypt your report, request the maintainer's OpenPGP key by
email first.

## Supported versions

The latest released version receives security fixes. gisp uses a single
linear version history.

## Threat model

gisp protects the **confidentiality and integrity of a file at rest** against
an attacker who later obtains the encrypted container but not the passphrase.

### In scope (what gisp defends against)

* **Recovery of the plaintext** from a container without the passphrase. The
  data is encrypted with XChaCha20-Poly1305 via libsodium's
  `crypto_secretstream`; the key is derived with Argon2id and a per-file random
  salt.
* **Tampering** with any part of the container. The full metadata header
  (version, KDF parameters, salt, declared length) is bound as additional
  authenticated data to every chunk, and each chunk is authenticated. Any
  modification causes decryption to fail.
* **Truncation** of the ciphertext. The final chunk carries a FINAL tag;
  missing trailing data is detected.
* **Denial of service via a hostile container.** KDF parameters and sizes read
  from an untrusted header are bounds-checked before use, with
  operator-configurable ceilings (`--max-opslimit`, `--max-memlimit`,
  `--max-filesize`). A header value can never relax an operator ceiling.
* **Secret exposure through swap or process memory.** Passphrases and keys are
  held in guarded, mlocked pages (`sodium_malloc`) and wiped after use.
* **Terminal leakage.** The passphrase prompt disables echo and restores the
  terminal even on interruption.
* **Output corruption.** Output to a named file is written to a temporary file
  and atomically renamed, with `fsync` of the file and its directory.

### Out of scope (explicitly not defended)

* **A compromised local machine** while gisp runs: a kernel-level attacker,
  malicious libc/libsodium, hardware implants, or a process able to read this
  process's memory (e.g. `ptrace` as the same user or root). gisp assumes the
  machine performing encryption/decryption is trusted.
* **A weak passphrase.** Argon2id raises the cost of guessing, but a guessable
  passphrase is recoverable. A minimum length is enforced
  (`--min-password-length`, default 12).
* **Permissions and atomicity when writing to standard output.** As a Unix
  filter (path `-`), gisp cannot enforce `0600` on a redirection target and
  cannot make a stream atomic; a non-zero exit means "discard the output."
  Named-file mode provides both guarantees.
* **Traffic analysis / metadata.** The container leaks its approximate size and
  the KDF parameters used. File names are not encrypted.
* **Side channels** outside libsodium's own constant-time guarantees.
* **Rollback/versioning, multi-recipient, key management, signatures.** gisp is
  symmetric, single-passphrase, single-file.

## Cryptographic construction

| Purpose | Primitive |
|---------|-----------|
| Authenticated encryption | XChaCha20-Poly1305 (`crypto_secretstream`) |
| Key derivation | Argon2id (`crypto_pwhash`) |
| Salt / nonces | `randombytes_buf` / secretstream-managed |
| Constant-time comparison | `sodium_memcmp` |

gisp implements no cryptographic primitives of its own; all are provided by
libsodium. The security-relevant code is the container framing and the parser,
which are covered by the test suite, sanitizers, fuzzers, and the size-math
verification under `proof/`.

---

Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>

Copying and distribution of this file, with or without modification, are
permitted in any medium without royalty provided the copyright notice and
this notice are preserved.  This file is offered as-is, without any warranty.
