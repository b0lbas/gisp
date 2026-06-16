/* src/crypto.c -- gisp encryption and decryption core.

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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "gisp.h"

int
encrypt_file (const char *prog, const char *in_path, const char *out_path,
              const char *password, size_t pass_len,
              unsigned long long opslimit, unsigned long long memlimit)
{
  int in_fd  = -1;
  int out_fd = -1;
  char *tmp_path  = NULL;
  unsigned char *key       = NULL;
  unsigned char *chunk_in  = NULL;
  unsigned char *chunk_out = NULL;
  int res       = 0;
  int64_t file_size = 0;

  crypto_secretstream_xchacha20poly1305_state state;
  unsigned char header_base[METADATA_BASE_SIZE];
  unsigned char stream_hdr[STREAM_HDR_SIZE];
  sodium_memzero (header_base, METADATA_BASE_SIZE);

  in_fd = safely_open_input (prog, in_path, &file_size);
  if (in_fd == -1)
    return 0;

  if (check_same_file (in_fd, out_path))
    {
      fprintf (stderr, "%s: error: input and output paths refer to the same file\n",
               prog);
      goto cleanup;
    }

  if ((uint64_t) file_size > MAX_VAULT_FILE_SIZE)
    {
      fprintf (stderr, "%s: error: file exceeds maximum allowed size (64 GiB)\n",
               prog);
      goto cleanup;
    }

  if (asprintf (&tmp_path, "%s.tmp", out_path) < 0)
    {
      tmp_path = NULL;
      goto cleanup;
    }

  out_fd = open (tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (out_fd == -1)
    {
      fprintf (stderr, "%s: %s: cannot create temporary output file: %s\n",
               prog, tmp_path, strerror (errno));
      goto cleanup;
    }

  key       = secure_malloc (KEY_SIZE);
  chunk_in  = secure_malloc (CHUNK_SIZE);
  chunk_out = secure_malloc (CHUNK_SIZE + CRYPTO_ABYTES);
  if (!key || !chunk_in || !chunk_out)
    {
      fprintf (stderr, "%s: error: out of memory\n", prog);
      goto cleanup;
    }

  memcpy (header_base + OFST_MAGIC,    VAULT_MAGIC, 4);
  serialize_uint16 (header_base + OFST_VERSION,  VAULT_VERSION);
  serialize_uint64 (header_base + OFST_OPSLIMIT, opslimit);
  serialize_uint64 (header_base + OFST_MEMLIMIT, memlimit);
  serialize_uint64 (header_base + OFST_PAYLOAD,  (uint64_t) file_size);
  randombytes_buf  (header_base + OFST_SALT,     SALT_SIZE);

  if (memlimit > (uint64_t) SIZE_MAX)
    {
      fprintf (stderr, "%s: error: memlimit exceeds addressable memory on this"
                       " platform\n", prog);
      goto cleanup;
    }

  if (crypto_pwhash (key, KEY_SIZE,
                     password, pass_len,
                     header_base + OFST_SALT,
                     opslimit, (size_t) memlimit,
                     crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
      fprintf (stderr, "%s: error: Argon2id failed"
                       " (insufficient memory for requested parameters)\n",
               prog);
      goto cleanup;
    }

  if (lseek (out_fd, HEADER_TOTAL_SIZE, SEEK_SET) < 0)
    goto cleanup;

  crypto_secretstream_xchacha20poly1305_init_push (&state, stream_hdr, key);

  int64_t remaining = file_size;
  do
    {
      size_t to_read = (remaining > (int64_t) CHUNK_SIZE)
                       ? CHUNK_SIZE
                       : (size_t) remaining;

      ssize_t got = read_all (in_fd, chunk_in, to_read);
      if (got < 0 || (size_t) got != to_read)
        {
          fprintf (stderr, "%s: error: read failed: %s\n",
                   prog, strerror (errno));
          goto cleanup;
        }

      unsigned char tag = (remaining == (int64_t) to_read)
                          ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
                          : 0;

      unsigned long long out_len;
      if (crypto_secretstream_xchacha20poly1305_push (
              &state, chunk_out, &out_len,
              chunk_in, to_read,
              header_base, METADATA_BASE_SIZE, tag) != 0)
        goto cleanup;

      if (write_all (out_fd, chunk_out, (size_t) out_len)
          != (ssize_t) out_len)
        {
          fprintf (stderr, "%s: error: write failed: %s\n",
                   prog, strerror (errno));
          goto cleanup;
        }

      remaining -= (int64_t) to_read;
    }
  while (remaining > 0);

  if (lseek (out_fd, 0, SEEK_SET) < 0)
    goto cleanup;
  if (write_all (out_fd, header_base, METADATA_BASE_SIZE)
      != (ssize_t) METADATA_BASE_SIZE)
    goto cleanup;
  if (write_all (out_fd, stream_hdr, STREAM_HDR_SIZE)
      != (ssize_t) STREAM_HDR_SIZE)
    goto cleanup;

  fprintf (stderr, "[+] File successfully encrypted.\n");
  res = 1;

cleanup:
  secure_free (chunk_out);
  secure_free (chunk_in);
  secure_free (key);
  sodium_memzero (&state, sizeof (state));
  if (in_fd  != -1) close (in_fd);
  if (out_fd != -1)
    {
      if (res && fsync (out_fd) != 0)
        {
          fprintf (stderr, "%s: error: fsync failed: %s\n",
                   prog, strerror (errno));
          res = 0;
        }
      close (out_fd);
    }
  if (res && tmp_path)
    {
      if (rename (tmp_path, out_path) != 0)
        {
          fprintf (stderr, "%s: error: cannot rename temporary file: %s\n",
                   prog, strerror (errno));
          unlink (tmp_path);
          res = 0;
        }
    }
  else if (tmp_path)
    {
      unlink (tmp_path);
    }
  free (tmp_path);
  return res;
}

int
decrypt_file (const char *prog, const char *in_path, const char *out_path,
              const char *password, size_t pass_len)
{
  int in_fd  = -1;
  int out_fd = -1;
  char *tmp_path  = NULL;
  unsigned char *key       = NULL;
  unsigned char *chunk_in  = NULL;
  unsigned char *chunk_out = NULL;
  int res       = 0;
  int64_t file_size = 0;

  crypto_secretstream_xchacha20poly1305_state state;
  unsigned char header_base[METADATA_BASE_SIZE];
  unsigned char stream_hdr[STREAM_HDR_SIZE];

  in_fd = safely_open_input (prog, in_path, &file_size);
  if (in_fd == -1)
    return 0;

  if (check_same_file (in_fd, out_path))
    {
      fprintf (stderr, "%s: error: input and output paths refer to the same file\n",
               prog);
      goto cleanup;
    }

  if (file_size < (int64_t) HEADER_TOTAL_SIZE)
    {
      fprintf (stderr, "%s: error: %s is too small to be a valid gisp container\n",
               prog, in_path);
      goto cleanup;
    }

  if (read_all (in_fd, header_base, METADATA_BASE_SIZE)
      != (ssize_t) METADATA_BASE_SIZE)
    goto cleanup;
  if (read_all (in_fd, stream_hdr, STREAM_HDR_SIZE)
      != (ssize_t) STREAM_HDR_SIZE)
    goto cleanup;

  if (memcmp (header_base + OFST_MAGIC, VAULT_MAGIC, 4) != 0
      || deserialize_uint16 (header_base + OFST_VERSION) != VAULT_VERSION)
    {
      fprintf (stderr, "%s: error: %s is not a valid gisp container\n",
               prog, in_path);
      goto cleanup;
    }

  unsigned long long opslimit = deserialize_uint64 (header_base + OFST_OPSLIMIT);
  unsigned long long memlimit = deserialize_uint64 (header_base + OFST_MEMLIMIT);
  uint64_t payload_len        = deserialize_uint64 (header_base + OFST_PAYLOAD);

  if (opslimit < crypto_pwhash_opslimit_min ()
      || opslimit > crypto_pwhash_opslimit_max ()
      || opslimit > MAX_ALLOWED_OPSLIMIT
      || memlimit < crypto_pwhash_memlimit_min ()
      || memlimit > crypto_pwhash_memlimit_max ()
      || memlimit > MAX_ALLOWED_MEMLIMIT)
    {
      fprintf (stderr, "%s: error: Argon2id parameters in header are out of range\n",
               prog);
      goto cleanup;
    }

  uint64_t expected_chunks = (payload_len == 0)
                             ? 1
                             : (payload_len + CHUNK_SIZE - 1) / CHUNK_SIZE;

  uint64_t auth_total;
  uint64_t expected_size;
  if (u64_mul_overflow (expected_chunks, (uint64_t) CRYPTO_ABYTES, &auth_total)
      || u64_add_overflow (auth_total, (uint64_t) HEADER_TOTAL_SIZE, &auth_total)
      || u64_add_overflow (auth_total, payload_len, &expected_size))
    {
      fprintf (stderr, "%s: error: container size calculation overflowed\n",
               prog);
      goto cleanup;
    }

  if (payload_len > MAX_VAULT_FILE_SIZE
      || expected_size != (uint64_t) file_size)
    {
      fprintf (stderr, "%s: error: container structure integrity check failed\n",
               prog);
      goto cleanup;
    }

  if (asprintf (&tmp_path, "%s.tmp", out_path) < 0)
    {
      tmp_path = NULL;
      goto cleanup;
    }

  out_fd = open (tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (out_fd == -1)
    {
      fprintf (stderr, "%s: %s: cannot create temporary output file: %s\n",
               prog, tmp_path, strerror (errno));
      goto cleanup;
    }

  key       = secure_malloc (KEY_SIZE);
  chunk_in  = secure_malloc (CHUNK_SIZE + CRYPTO_ABYTES);
  chunk_out = secure_malloc (CHUNK_SIZE);
  if (!key || !chunk_in || !chunk_out)
    {
      fprintf (stderr, "%s: error: out of memory\n", prog);
      goto cleanup;
    }

  if (memlimit > (uint64_t) SIZE_MAX)
    {
      fprintf (stderr, "%s: error: memlimit exceeds addressable memory on this"
                       " platform\n", prog);
      goto cleanup;
    }

  if (crypto_pwhash (key, KEY_SIZE,
                     password, pass_len,
                     header_base + OFST_SALT,
                     opslimit, (size_t) memlimit,
                     crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
      fprintf (stderr, "%s: error: Argon2id failed"
                       " (insufficient memory for requested parameters)\n",
               prog);
      goto cleanup;
    }

  if (crypto_secretstream_xchacha20poly1305_init_pull (&state, stream_hdr, key) != 0)
    {
      fprintf (stderr, "%s: error: stream initialisation failed\n", prog);
      goto cleanup;
    }

  uint64_t remaining = payload_len;
  do
    {
      size_t to_read_plain = (remaining > CHUNK_SIZE)
                             ? CHUNK_SIZE
                             : (size_t) remaining;
      size_t to_read_enc   = to_read_plain + CRYPTO_ABYTES;
      ssize_t got = read_all (in_fd, chunk_in, to_read_enc);
      if (got < 0 || (size_t) got != to_read_enc)
        {
          fprintf (stderr, "%s: error: read failed: %s\n",
                   prog, strerror (errno));
          goto cleanup;
        }
      unsigned char tag;
      unsigned long long out_len;
      if (crypto_secretstream_xchacha20poly1305_pull (
              &state, chunk_out, &out_len, &tag,
              chunk_in, to_read_enc,
              header_base, METADATA_BASE_SIZE) != 0)
        {
          fprintf (stderr, "%s: error: authentication failed"
                           " (wrong password or corrupted file)\n", prog);
          goto cleanup;
        }
      if (remaining == to_read_plain
          && tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL)
        {
          fprintf (stderr, "%s: error: stream truncation detected\n", prog);
          goto cleanup;
        }
      if (write_all (out_fd, chunk_out, (size_t) out_len)
          != (ssize_t) out_len)
        {
          fprintf (stderr, "%s: error: write failed: %s\n",
                   prog, strerror (errno));
          goto cleanup;
        }
      remaining -= to_read_plain;
    }
  while (remaining > 0);

  fprintf (stderr, "[+] File successfully decrypted.\n");
  res = 1;

cleanup:
  secure_free (chunk_in);
  secure_free (chunk_out);
  secure_free (key);
  sodium_memzero (&state, sizeof (state));
  if (in_fd  != -1) close (in_fd);
  if (out_fd != -1)
    {
      if (res && fsync (out_fd) != 0)
        {
          fprintf (stderr, "%s: error: fsync failed: %s\n",
                   prog, strerror (errno));
          res = 0;
        }
      close (out_fd);
    }
  if (res && tmp_path)
    {
      if (rename (tmp_path, out_path) != 0)
        {
          fprintf (stderr, "%s: error: cannot rename temporary file: %s\n",
                   prog, strerror (errno));
          unlink (tmp_path);
          res = 0;
        }
    }
  else if (tmp_path)
    {
      unlink (tmp_path);
    }
  free (tmp_path);
  return res;
}
