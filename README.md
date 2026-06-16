# gisp — Fast and Secure File Encryption

`gisp` is a file encryption utility that uses **XChaCha20-Poly1305** for authenticated encryption and **Argon2id** for key derivation. It is designed with security-first principles, including signal-safe terminal handling and memory hardening.

## Features

- **Authenticated Encryption:** Uses libsodium's `crypto_secretstream` (XChaCha20-Poly1305) with AAD binding the entire container header to every chunk.
- **Argon2id KDF:** High-resistance to GPU/ASIC cracking with customizable CPU and memory limits.
- **Memory Hardening:** Sensitive data is stored in memory locked and guarded pages (`sodium_malloc`).
- **Signal Safety:** Atomically restores terminal state on interrupts (Ctrl+C, Ctrl+Z).
- **Atomic Operations:** Writes to temporary files with `O_EXCL` and uses `fsync` + `rename` for atomic replacement.
- **DoS Protection:** Enforces strict limits on KDF parameters stored in headers.

## Build and Install

### Prerequisites

- `libsodium` (library and headers)
- `gcc`
- `make`

### Building

```bash
make
```

### Running Tests

```bash
make test
```

### Installation

```bash
sudo make install
```

## Usage

### Encrypt a file
```bash
./gisp -e data.txt -o data.gisp
```

### Decrypt a file
```bash
./gisp -d data.gisp -o restored.txt
```

### Advanced KDF Parameters
```bash
./gisp -e data.txt -o data.gisp --opslimit 16 --memlimit 1073741824
```

## Maintainer

**Uladzislau Bolbas** — [cmrtumilovic@gmail.com](mailto:cmrtumilovic@gmail.com)

## License

GPL-3.0 or later. See headers in source files.
