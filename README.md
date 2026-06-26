# gisp — Fast and Secure File Encryption

`gisp` is a file encryption utility that uses **XChaCha20-Poly1305** for authenticated encryption and **Argon2id** for key derivation. It is designed with security-first principles, including signal-safe terminal handling and memory hardening.

## Features

- **Authenticated Encryption:** Uses libsodium's `crypto_secretstream` (XChaCha20-Poly1305) with AAD binding the entire container header to every chunk.
- **Argon2id KDF:** High-resistance to GPU/ASIC cracking with customizable CPU and memory limits.
- **Memory Hardening:** Sensitive data is stored in memory locked and guarded pages (`sodium_malloc`).
- **Signal Safety:** Atomically restores terminal state on interrupts (Ctrl+C, Ctrl+Z).
- **Atomic Operations:** Writes to temporary files with `O_EXCL` and uses `fsync` + `rename` for atomic replacement.
- **DoS Protection:** Enforces strict, operator-configurable limits on KDF parameters and sizes; a container header can never relax an operator ceiling.
- **Pipe Friendly:** A path of `-` reads standard input or writes standard output, so `gisp` works as a filter.
- **Internationalized:** Messages are translatable via GNU gettext.

## Build and Install

### Prerequisites

- `libsodium` (library and headers)
- A C compiler and `make`
- To build from a git checkout: GNU Autoconf, Automake, gettext (`autopoint`)
  and, optionally, Texinfo for the manual

### Building

From a released tarball:

```bash
./configure
make
make check
sudo make install
```

From a git checkout, regenerate the build system first:

```bash
./autogen.sh
./configure
make
```

## Usage

### Encrypt / decrypt a file
```bash
gisp -e data.txt -o data.gisp
gisp -d data.gisp -o restored.txt
```

### Use in a pipeline (non-interactive passphrase)
```bash
tar c dir | gisp -e - -o - --passphrase-fd 3 3<key > dir.gisp
gisp -d - -o - --passphrase-fd 3 3<key < dir.gisp | tar x
```

### Advanced KDF parameters
```bash
gisp -e data.txt -o data.gisp --opslimit 16 --memlimit 1073741824
```

See the manual (`info gisp`) for the full option list, the two-class limit
model, the security notes, and the container format specification.

## Maintainer

**Uladzislau Bolbas** — [cmrtumilovic@gmail.com](mailto:cmrtumilovic@gmail.com)

Project Link: [https://savannah.nongnu.org/projects/gisp](https://savannah.nongnu.org/projects/gisp)

## License

Copyright (C) 2026 Uladzislau Bolbas.

gisp is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. There is NO WARRANTY, to the extent permitted by law.

See the [COPYING](COPYING) file for the full license text, and the headers
in each source file for the per-file notices.
