/* gisp.h -- gisp file encryption/decryption utility.

   Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>

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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <sodium.h>

#include "gettext.h"

/* Package identity.  Under Autotools these come from config.h; the fallbacks
   keep the plain Makefile build (and editors) working.  */
#ifndef PACKAGE
# define PACKAGE "gisp"
#endif
#ifndef VERSION
# define VERSION "1.1"
#endif
#ifndef PACKAGE_BUGREPORT
# define PACKAGE_BUGREPORT "cmrtumilovic@gmail.com"
#endif
#ifndef LOCALEDIR
# define LOCALEDIR "/usr/local/share/locale"
#endif

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

/* Stored in the payload-length field of a streamed container.  When the input
   is a pipe the plaintext length is unknown at the time the header must be
   written, so this sentinel is used and end-of-stream is proven by the
   secretstream FINAL tag rather than by a length comparison.  */
#define PAYLOAD_LEN_UNKNOWN UINT64_MAX

#define PROGRAM_NAME  "gisp"

/* On-disk container layout (all multi-byte fields little-endian):

     offset  size  field
     ------  ----  ----------------------------------------------------------
        0      4   MAGIC      "GISP"
        4      2   VERSION    format version (currently 1)
        6      8   OPSLIMIT   Argon2id ops cost
       14      8   MEMLIMIT   Argon2id memory cost, bytes
       22  SALT_SIZE SALT     per-file random salt
       22+S    8   PAYLOAD    plaintext length, or PAYLOAD_LEN_UNKNOWN (stream)
     ----------------------- METADATA_BASE_SIZE -----------------------------
       ...  STREAM_HDR_SIZE   libsodium secretstream header
     ----------------------- HEADER_TOTAL_SIZE ------------------------------
       ...      ...           chunks: ciphertext + CRYPTO_ABYTES tag each

   The METADATA_BASE_SIZE prefix is authenticated as AAD on every chunk, so a
   single bit flipped anywhere in it makes decryption fail.  */
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

/* A path of "-" selects standard input/output instead of a named file.
   Accepts NULL (treated as "not a stream") so callers need no extra guard.  */
int     is_stdio (const char *path);

void   *secure_malloc (size_t size);
void    secure_free (void *ptr);

ssize_t read_all (int fd, unsigned char *buf, size_t size);
ssize_t write_all (int fd, const unsigned char *buf, size_t size);

void     serialize_uint16 (unsigned char *buf, uint16_t val);
uint16_t deserialize_uint16 (const unsigned char *buf);
void     serialize_uint64 (unsigned char *buf, uint64_t val);
uint64_t deserialize_uint64 (const unsigned char *buf);

/* Checked 64-bit arithmetic on sizes taken from an untrusted header.  Exported
   (not static) so proof/overflow_proof.c can exercise them directly against an
   exhaustive reference.  Each returns non-zero on overflow.  */
int u64_add_overflow (uint64_t a, uint64_t b, uint64_t *result);
int u64_mul_overflow (uint64_t a, uint64_t b, uint64_t *result);

/* Compute the exact on-disk container size for PAYLOAD_LEN bytes of plaintext
   (header + per-chunk authentication tags).  Returns non-zero on overflow.
   The single source of truth for the decrypt-side size check, verified in
   proof/overflow_proof.c.  */
int container_size_for_payload (uint64_t payload_len, uint64_t *result);

int check_same_file (int fd1, const char *path2);
int safely_open_input (const char *prog, const char *path, int64_t *out_size);
int fsync_dir (const char *path);

/* ---------------------------------------------------------------------------
   Terminal and Signal handling (src/terminal.c).
   --------------------------------------------------------------------------- */

int     terminal_init_signals (void);

/* Read one line of passphrase (up to MAX_LEN-1 bytes) into BUF.  Both readers
   return the stored length, or -1 on error/empty input, and set *TRUNCATED to
   1 when the line was longer than the buffer and the excess was discarded.
   TRUNCATED may be NULL if the caller does not care.  */
ssize_t get_password_secure (const char *prompt, char *buf, size_t max_len,
                             int *truncated);

/* Read a single line of passphrase from an already-open descriptor (a pipe,
   a regular file, or a user-supplied fd).  No echo handling: the source is
   not assumed to be a terminal.  Used for non-interactive pipelines.  */
ssize_t read_password_fd (int fd, char *buf, size_t max_len, int *truncated);

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

/* Override the operator-side resource ceilings used to reject hostile or
   over-costly containers.  These protect the machine doing the work, so the
   operator may raise or lower them; a value carried in a container header can
   never relax them.  Defaults match the MAX_ALLOWED_* / MAX_VAULT_FILE_SIZE
   macros.  Passing 0 for any argument leaves that ceiling unchanged.  */
void gisp_set_limits (unsigned long long max_opslimit,
                      unsigned long long max_memlimit,
                      uint64_t max_filesize);

#endif /* GISP_H */
