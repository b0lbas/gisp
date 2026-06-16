/* gisp.h -- gisp file encryption/decryption utility.

   Copyright (C) 2025 Uladzislau Bolbas <cmrtumilovic@gmail.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

#ifndef GISP_H
#define GISP_H

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <sodium.h>

/* ---------------------------------------------------------------------------
   Cryptographic constants and layout macros.
   --------------------------------------------------------------------------- */

#define KEY_SIZE         crypto_secretstream_xchacha20poly1305_KEYBYTES
#define SALT_SIZE        crypto_pwhash_SALTBYTES
#define STREAM_HDR_SIZE  crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define CRYPTO_ABYTES    crypto_secretstream_xchacha20poly1305_ABYTES

#define MAX_PASS_LEN 512
#define MIN_PASS_LEN 12
#define CHUNK_SIZE 65536
#define MAX_VAULT_FILE_SIZE (64ULL * 1024 * 1024 * 1024)
#define MAX_ALLOWED_MEMLIMIT (4ULL * 1024 * 1024 * 1024)
#define MAX_ALLOWED_OPSLIMIT 32ULL

#define VAULT_MAGIC   "GISP"
#define VAULT_VERSION 1

#define PROGRAM_NAME  "gisp"

#define OFST_MAGIC    0
#define OFST_VERSION  4
#define OFST_OPSLIMIT 6
#define OFST_MEMLIMIT 14
#define OFST_SALT     22
#define OFST_PAYLOAD  (22 + SALT_SIZE)

#define METADATA_BASE_SIZE (OFST_PAYLOAD + 8)
#define HEADER_TOTAL_SIZE  (METADATA_BASE_SIZE + STREAM_HDR_SIZE)

/* ---------------------------------------------------------------------------
   Common utilities (src/common.c).
   --------------------------------------------------------------------------- */

void   *secure_malloc (size_t size);
void    secure_free (void *ptr);

ssize_t read_all (int fd, unsigned char *buf, size_t size);
ssize_t write_all (int fd, const unsigned char *buf, size_t size);

void     serialize_uint16 (unsigned char *buf, uint16_t val);
uint16_t deserialize_uint16 (const unsigned char *buf);
void     serialize_uint64 (unsigned char *buf, uint64_t val);
uint64_t deserialize_uint64 (const unsigned char *buf);

int u64_add_overflow (uint64_t a, uint64_t b, uint64_t *result);
int u64_mul_overflow (uint64_t a, uint64_t b, uint64_t *result);

int check_same_file (int fd1, const char *path2);
int safely_open_input (const char *prog, const char *path, int64_t *out_size);
int fsync_dir (const char *path);

/* ---------------------------------------------------------------------------
   Terminal and Signal handling (src/terminal.c).
   --------------------------------------------------------------------------- */

int     terminal_init_signals (void);
ssize_t get_password_secure (const char *prompt, char *buf, size_t max_len);

/* ---------------------------------------------------------------------------
   Cryptographic core (src/crypto.c).
   --------------------------------------------------------------------------- */

int encrypt_file (const char *prog, const char *in_path,
                  const char *out_path, const char *password,
                  size_t pass_len,
                  unsigned long long opslimit, unsigned long long memlimit);
int decrypt_file (const char *prog, const char *in_path,
                  const char *out_path, const char *password,
                  size_t pass_len);

#endif /* GISP_H */
