# OpenSSF Best Practices — self-assessment

Working notes for the OpenSSF Best Practices Badge
(<https://www.bestpractices.dev/>). Register the project there and transcribe
these answers; this file tracks current status. Status: **MET** / **PARTIAL** /
**TODO** (the last few are external actions that cannot be done from the repo).

## Basics
- **Project homepage / description** — MET (README, Savannah project page).
- **FLOSS license** — MET (GPLv3-or-later, `COPYING`, per-file notices).
- **Documentation: basic + reference** — MET (`README.md`, `gisp.1`, Texinfo
  manual under `doc/`, container-format spec in the manual).
- **English for communication** — MET.

## Change control
- **Public version-controlled source** — MET (Codeberg; Savannah pending).
- **Unique version numbering / release notes** — MET (`NEWS`, semantic 1.0).

## Reporting
- **Bug/vulnerability reporting process** — MET (`SECURITY.md`, bug address in
  `--help` and the manual).
- **Vulnerability report private channel** — MET (`SECURITY.md`).

## Quality
- **Working build system** — MET (GNU Autotools; `./configure && make`).
- **Automated test suite** — MET (`make check`: unit + CLI + known-answer
  vectors; fault-injection and fuzzing available).
- **New-functionality tests policy** — MET (tests added with features; see
  `tests/`).
- **Warning flags** — MET (clean under `-Wall -Wextra -Wconversion
  -Wsign-conversion` and more; `gcc -fanalyzer` and `clang --analyze` clean).

## Security
- **Secure development knowledge** — MET (uses a vetted crypto library;
  documented threat model).
- **Use of good cryptographic practices** — MET (libsodium: XChaCha20-Poly1305
  + Argon2id; per-file salt; constant-time compare; no home-grown crypto).
- **Secured delivery against MITM** — PARTIAL (HTTPS hosting; **signed release
  tarballs**: see `doc/RELEASING.md` — set up the signing key — TODO).
- **No leaked private credentials** — MET.
- **Hardening** — MET (PIE, full RELRO, stack canary, FORTIFY, non-exec stack;
  see `--enable-hardening`, default on).

## Analysis
- **Static analysis** — MET (`gcc -fanalyzer`, `clang --analyze`, `clang-tidy`;
  recommend adding Coverity Scan: `doc/coverity.md`).
- **Dynamic analysis** — MET (ASan + UBSan on the suite; libFuzzer harnesses in
  `fuzz/`; fault injection in `tests/`; size-math verification in `proof/`).

## Remaining external actions (cannot be done from the repository)
- [ ] Register the project on bestpractices.dev and submit these answers.
- [ ] Set up a release signing (OpenPGP) key and sign tarballs (`doc/RELEASING.md`).
- [ ] Enable Coverity Scan / a CI badge (`doc/coverity.md`).
- [ ] (Higher tiers) two-person review for releases; OpenSSF Scorecard in CI.
