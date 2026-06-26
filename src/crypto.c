/* src/crypto.c -- gisp encryption and decryption core.

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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "gisp.h"

/* Operator-side resource ceilings.  They protect the machine doing the work
   from a hostile or over-costly container, so the operator may raise or lower
   them; a value carried in a header is always clamped against these and can
   never relax them.  Defaults match the compile-time maxima.  */
static unsigned long long g_max_opslimit = MAX_ALLOWED_OPSLIMIT;
static unsigned long long g_max_memlimit = MAX_ALLOWED_MEMLIMIT;
static uint64_t           g_max_filesize = MAX_VAULT_FILE_SIZE;

void
gisp_set_limits (unsigned long long max_opslimit,
                 unsigned long long max_memlimit,
                 uint64_t max_filesize)
{
  if (max_opslimit)
    g_max_opslimit = max_opslimit;
  if (max_memlimit)
    g_max_memlimit = max_memlimit;
  if (max_filesize)
    g_max_filesize = max_filesize;
}

/* A path of "-" selects the standard stream instead of a named file.  */
static int
is_stdio (const char *path)
{
  return path[0] == '-' && path[1] == '\0';
}

int
encrypt_file (const char *prog, const char *in_path, const char *out_path,
              const char *password, size_t pass_len,
              unsigned long long opslimit, unsigned long long memlimit)
{
  int in_fd  = -1;
  int out_fd = -1;
  int in_is_pipe  = 0;   /* input is stdin: length unknown, do not close.  */
  int out_is_file = 0;   /* output is a named file: atomic temp + rename.  */
  char *tmp_path  = NULL;
  unsigned char *key       = NULL;
  unsigned char *chunk_in  = NULL;
  unsigned char *chunk_out = NULL;
  int res       = 0;
  int64_t file_size = -1;

  crypto_secretstream_xchacha20poly1305_state state;
  unsigned char header_base[METADATA_BASE_SIZE];
  unsigned char stream_hdr[STREAM_HDR_SIZE];
  sodium_memzero (header_base, METADATA_BASE_SIZE);

  /* Enforce the operator ceiling on the requested cost here, the single place
     it is checked, rather than relying on the caller.  */
  if (opslimit > g_max_opslimit || memlimit > g_max_memlimit)
    {
      fprintf (stderr,
               _("%s: error: requested KDF limits exceed the maximum allowed\n"),
               prog);
      return 0;
    }

  /* Open the input.  A pipe has no stattable length, so its container is
     written in streaming form (see below).  */
  if (is_stdio (in_path))
    {
      in_fd      = STDIN_FILENO;
      in_is_pipe = 1;
    }
  else
    {
      in_fd = safely_open_input (prog, in_path, &file_size);
      if (in_fd == -1)
        return 0;
    }

  /* Open the output.  Only a named file gets the atomic temp-file treatment;
     stdout is written through as a stream.  */
  if (is_stdio (out_path))
    {
      out_fd = STDOUT_FILENO;
    }
  else
    {
      out_is_file = 1;

      /* Refuse to encrypt onto the source: we read it incrementally, so
         writing the container over it would corrupt the plaintext.  Only
         meaningful when the input is a real file.  */
      if (!in_is_pipe && check_same_file (in_fd, out_path))
        {
          fprintf (stderr,
                   _("%s: error: input and output paths refer to the same file\n"),
                   prog);
          goto cleanup;
        }

      if (asprintf (&tmp_path, "%s.tmp", out_path) < 0)
        {
          tmp_path = NULL;
          goto cleanup;
        }

      /* Write to a temporary file first, then rename into place, so a crash
         or wrong password can never leave a half-written container at the
         real path.  O_EXCL makes creation fail rather than follow a symlink
         planted at tmp_path; 0600 keeps the ciphertext private from creation.  */
      out_fd = open (tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
      if (out_fd == -1)
        {
          fprintf (stderr, _("%s: %s: cannot create temporary output file: %s\n"),
                   prog, tmp_path, strerror (errno));
          goto cleanup;
        }
    }

  if (!in_is_pipe && (uint64_t) file_size > g_max_filesize)
    {
      fprintf (stderr, _("%s: error: file exceeds the maximum allowed size\n"),
               prog);
      goto cleanup;
    }

  key       = secure_malloc (KEY_SIZE);
  chunk_in  = secure_malloc (CHUNK_SIZE);
  chunk_out = secure_malloc (CHUNK_SIZE + CRYPTO_ABYTES);
  if (!key || !chunk_in || !chunk_out)
    {
      fprintf (stderr, _("%s: error: out of memory\n"), prog);
      goto cleanup;
    }

  memcpy (header_base + OFST_MAGIC,    VAULT_MAGIC, 4);
  serialize_uint16 (header_base + OFST_VERSION,  VAULT_VERSION);
  serialize_uint64 (header_base + OFST_OPSLIMIT, opslimit);
  serialize_uint64 (header_base + OFST_MEMLIMIT, memlimit);
  /* A streamed container cannot know its length yet; the FINAL tag proves the
     end of stream instead.  */
  serialize_uint64 (header_base + OFST_PAYLOAD,
                    in_is_pipe ? PAYLOAD_LEN_UNKNOWN : (uint64_t) file_size);
  /* A fresh random salt per file means the same password yields a different
     key every time, defeating precomputation and cross-file comparison.  */
  randombytes_buf  (header_base + OFST_SALT,     SALT_SIZE);

  if (memlimit > (uint64_t) SIZE_MAX)
    {
      fprintf (stderr, _("%s: error: memlimit exceeds addressable memory on this"
                         " platform\n"), prog);
      goto cleanup;
    }

  if (crypto_pwhash (key, KEY_SIZE,
                     password, pass_len,
                     header_base + OFST_SALT,
                     opslimit, (size_t) memlimit,
                     crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
      fprintf (stderr, _("%s: error: Argon2id failed"
                         " (insufficient memory for requested parameters)\n"),
               prog);
      goto cleanup;
    }

  crypto_secretstream_xchacha20poly1305_init_push (&state, stream_hdr, key);

  /* Write the header first.  This produces exactly the same bytes as seeking
     back would, but needs no seek, so it works on a pipe as well as a file.  */
  if (write_all (out_fd, header_base, METADATA_BASE_SIZE)
      != (ssize_t) METADATA_BASE_SIZE
      || write_all (out_fd, stream_hdr, STREAM_HDR_SIZE)
      != (ssize_t) STREAM_HDR_SIZE)
    {
      fprintf (stderr, _("%s: error: write failed: %s\n"), prog, strerror (errno));
      goto cleanup;
    }

  if (!in_is_pipe)
    {
      /* Known length: chunk by exact size and tag the last chunk FINAL.  */
      int64_t remaining = file_size;
      do
        {
          size_t to_read = (remaining > (int64_t) CHUNK_SIZE)
                           ? CHUNK_SIZE
                           : (size_t) remaining;

          ssize_t got = read_all (in_fd, chunk_in, to_read);
          if (got < 0 || (size_t) got != to_read)
            {
              fprintf (stderr, _("%s: error: read failed: %s\n"),
                       prog, strerror (errno));
              goto cleanup;
            }

          /* Tag the last chunk FINAL so decryption can prove the stream was
             not truncated; bind the full header as AAD on every chunk so any
             tampering with the metadata makes authentication fail.  */
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
              fprintf (stderr, _("%s: error: write failed: %s\n"),
                       prog, strerror (errno));
              goto cleanup;
            }

          remaining -= (int64_t) to_read;
        }
      while (remaining > 0);
    }
  else
    {
      /* Streaming: length unknown, so read until EOF.  read_all only returns
         a short count at EOF, which marks the final chunk; an input that is an
         exact multiple of CHUNK_SIZE simply emits a trailing empty FINAL
         chunk.  Enforce the size ceiling incrementally since we cannot stat.  */
      uint64_t total = 0;
      for (;;)
        {
          ssize_t got = read_all (in_fd, chunk_in, CHUNK_SIZE);
          if (got < 0)
            {
              fprintf (stderr, _("%s: error: read failed: %s\n"),
                       prog, strerror (errno));
              goto cleanup;
            }

          int is_final = ((size_t) got < CHUNK_SIZE);

          if (u64_add_overflow (total, (uint64_t) got, &total)
              || total > g_max_filesize)
            {
              fprintf (stderr,
                       _("%s: error: input exceeds the maximum allowed size\n"),
                       prog);
              goto cleanup;
            }

          unsigned char tag = is_final
                              ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
                              : 0;
          unsigned long long out_len;
          if (crypto_secretstream_xchacha20poly1305_push (
                  &state, chunk_out, &out_len,
                  chunk_in, (size_t) got,
                  header_base, METADATA_BASE_SIZE, tag) != 0)
            goto cleanup;

          if (write_all (out_fd, chunk_out, (size_t) out_len)
              != (ssize_t) out_len)
            {
              fprintf (stderr, _("%s: error: write failed: %s\n"),
                       prog, strerror (errno));
              goto cleanup;
            }

          if (is_final)
            break;
        }
    }

  fprintf (stderr, _("%s: file successfully encrypted\n"), prog);
  res = 1;

/* Single exit point reached on both success and every error via goto, so
   buffers are always wiped and freed and no temporary file is left behind.  */
cleanup:
  secure_free (chunk_out);
  secure_free (chunk_in);
  secure_free (key);
  /* The stream state holds key material on the stack; zero it explicitly.  */
  sodium_memzero (&state, sizeof (state));
  if (in_fd != -1 && !in_is_pipe)
    close (in_fd);
  if (out_fd != -1 && out_is_file)
    {
      /* Flush data to disk before the rename: the rename is only meaningful
         once the bytes it points at are actually durable.  (A stream to stdout
         gets neither fsync nor rename -- that is the Unix filter contract.)  */
      if (res && fsync (out_fd) != 0)
        {
          fprintf (stderr, _("%s: error: fsync failed: %s\n"),
                   prog, strerror (errno));
          res = 0;
        }
      close (out_fd);
    }
  if (out_is_file && res && tmp_path)
    {
      /* rename() is atomic on success, so a reader sees either the old file
         or the complete new one, never a partial container.  */
      if (rename (tmp_path, out_path) != 0)
        {
          fprintf (stderr, _("%s: error: cannot rename temporary file: %s\n"),
                   prog, strerror (errno));
          unlink (tmp_path);
          res = 0;
        }
      else if (fsync_dir (out_path) != 0)
        {
          fprintf (stderr, _("%s: warning: failed to sync parent directory: %s\n"),
                   prog, strerror (errno));
        }
    }
  else if (out_is_file && tmp_path)
    {
      /* Failure path: drop the half-written temporary.  */
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
  int in_is_pipe  = 0;
  int out_is_file = 0;
  char *tmp_path  = NULL;
  unsigned char *key       = NULL;
  unsigned char *chunk_in  = NULL;
  unsigned char *chunk_out = NULL;
  int res       = 0;
  int64_t file_size = -1;

  crypto_secretstream_xchacha20poly1305_state state;
  unsigned char header_base[METADATA_BASE_SIZE];
  unsigned char stream_hdr[STREAM_HDR_SIZE];

  if (is_stdio (in_path))
    {
      in_fd      = STDIN_FILENO;
      in_is_pipe = 1;
    }
  else
    {
      in_fd = safely_open_input (prog, in_path, &file_size);
      if (in_fd == -1)
        return 0;
    }

  /* For a seekable container we can sanity-check the size up front; a pipe
     simply fails the header read below if it is too short.  */
  if (!in_is_pipe && file_size < (int64_t) HEADER_TOTAL_SIZE)
    {
      fprintf (stderr,
               _("%s: error: %s is too small to be a valid gisp container\n"),
               prog, in_path);
      goto cleanup;
    }

  if (read_all (in_fd, header_base, METADATA_BASE_SIZE)
      != (ssize_t) METADATA_BASE_SIZE
      || read_all (in_fd, stream_hdr, STREAM_HDR_SIZE)
      != (ssize_t) STREAM_HDR_SIZE)
    {
      fprintf (stderr,
               _("%s: error: %s is too small to be a valid gisp container\n"),
               prog, in_path);
      goto cleanup;
    }

  if (memcmp (header_base + OFST_MAGIC, VAULT_MAGIC, 4) != 0
      || deserialize_uint16 (header_base + OFST_VERSION) != VAULT_VERSION)
    {
      fprintf (stderr, _("%s: error: %s is not a valid gisp container\n"),
               prog, in_path);
      goto cleanup;
    }

  unsigned long long opslimit = deserialize_uint64 (header_base + OFST_OPSLIMIT);
  unsigned long long memlimit = deserialize_uint64 (header_base + OFST_MEMLIMIT);
  uint64_t payload_len        = deserialize_uint64 (header_base + OFST_PAYLOAD);

  /* The KDF parameters come straight from an untrusted file and feed an
     allocation, so they must be bounded before use.  These bytes are not yet
     authenticated (the key derived from them is what authenticates), so the
     check has to happen here, before crypto_pwhash runs.  */
  if (opslimit < crypto_pwhash_opslimit_min ()
      || opslimit > crypto_pwhash_opslimit_max ()
      || opslimit > g_max_opslimit
      || memlimit < crypto_pwhash_memlimit_min ()
      || memlimit > crypto_pwhash_memlimit_max ()
      || memlimit > g_max_memlimit)
    {
      fprintf (stderr,
               _("%s: error: Argon2id parameters in header are out of range\n"),
               prog);
      goto cleanup;
    }

  /* A streamed container stores the sentinel length and is validated by the
     FINAL tag alone; a fixed-length container additionally gets the cheap
     structural size check below.  */
  int streamed = (payload_len == PAYLOAD_LEN_UNKNOWN);

  if (!streamed)
    {
      /* Derive the exact on-disk size the header claims and compare it against
         the real file size.  The helper does overflow-safe arithmetic so a
         crafted payload_len cannot wrap around and pass the check.  */
      uint64_t expected_size;
      if (container_size_for_payload (payload_len, &expected_size))
        {
          fprintf (stderr,
                   _("%s: error: container size calculation overflowed\n"), prog);
          goto cleanup;
        }

      if (payload_len > g_max_filesize
          || (!in_is_pipe && expected_size != (uint64_t) file_size))
        {
          fprintf (stderr,
                   _("%s: error: container structure integrity check failed\n"),
                   prog);
          goto cleanup;
        }
    }

  if (is_stdio (out_path))
    {
      out_fd = STDOUT_FILENO;
    }
  else
    {
      out_is_file = 1;

      if (!in_is_pipe && check_same_file (in_fd, out_path))
        {
          fprintf (stderr,
                   _("%s: error: input and output paths refer to the same file\n"),
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
          fprintf (stderr, _("%s: %s: cannot create temporary output file: %s\n"),
                   prog, tmp_path, strerror (errno));
          goto cleanup;
        }
    }

  key       = secure_malloc (KEY_SIZE);
  chunk_in  = secure_malloc (CHUNK_SIZE + CRYPTO_ABYTES);
  chunk_out = secure_malloc (CHUNK_SIZE);
  if (!key || !chunk_in || !chunk_out)
    {
      fprintf (stderr, _("%s: error: out of memory\n"), prog);
      goto cleanup;
    }

  if (memlimit > (uint64_t) SIZE_MAX)
    {
      fprintf (stderr, _("%s: error: memlimit exceeds addressable memory on this"
                         " platform\n"), prog);
      goto cleanup;
    }

  if (crypto_pwhash (key, KEY_SIZE,
                     password, pass_len,
                     header_base + OFST_SALT,
                     opslimit, (size_t) memlimit,
                     crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
      fprintf (stderr, _("%s: error: Argon2id failed"
                         " (insufficient memory for requested parameters)\n"),
               prog);
      goto cleanup;
    }

  if (crypto_secretstream_xchacha20poly1305_init_pull (&state, stream_hdr, key) != 0)
    {
      fprintf (stderr, _("%s: error: stream initialisation failed\n"), prog);
      goto cleanup;
    }

  if (!streamed)
    {
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
              fprintf (stderr, _("%s: error: read failed: %s\n"),
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
              fprintf (stderr, _("%s: error: authentication failed"
                                 " (wrong password or corrupted file)\n"), prog);
              goto cleanup;
            }
          /* On the last expected chunk the stream must also report FINAL; a
             mismatch means bytes were cut from the end.  */
          if (remaining == to_read_plain
              && tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL)
            {
              fprintf (stderr, _("%s: error: stream truncation detected\n"), prog);
              goto cleanup;
            }
          if (write_all (out_fd, chunk_out, (size_t) out_len)
              != (ssize_t) out_len)
            {
              fprintf (stderr, _("%s: error: write failed: %s\n"),
                       prog, strerror (errno));
              goto cleanup;
            }
          remaining -= to_read_plain;
        }
      while (remaining > 0);
    }
  else
    {
      /* No length to drive the loop: read chunks until one carries FINAL.
         Reaching EOF first, or a short non-final read, means truncation -- and
         because every chunk authenticates, no forged data can reach the
         output.  The size ceiling is enforced incrementally.  */
      uint64_t total = 0;
      for (;;)
        {
          ssize_t got = read_all (in_fd, chunk_in, CHUNK_SIZE + CRYPTO_ABYTES);
          if (got < 0)
            {
              fprintf (stderr, _("%s: error: read failed: %s\n"),
                       prog, strerror (errno));
              goto cleanup;
            }
          if (got == 0)
            {
              fprintf (stderr, _("%s: error: stream truncation detected\n"), prog);
              goto cleanup;
            }
          if ((size_t) got < CRYPTO_ABYTES)
            {
              fprintf (stderr, _("%s: error: authentication failed"
                                 " (wrong password or corrupted file)\n"), prog);
              goto cleanup;
            }

          unsigned char tag;
          unsigned long long out_len;
          if (crypto_secretstream_xchacha20poly1305_pull (
                  &state, chunk_out, &out_len, &tag,
                  chunk_in, (size_t) got,
                  header_base, METADATA_BASE_SIZE) != 0)
            {
              fprintf (stderr, _("%s: error: authentication failed"
                                 " (wrong password or corrupted file)\n"), prog);
              goto cleanup;
            }

          if (u64_add_overflow (total, out_len, &total)
              || total > g_max_filesize)
            {
              fprintf (stderr,
                       _("%s: error: plaintext exceeds the maximum allowed size\n"),
                       prog);
              goto cleanup;
            }

          if (write_all (out_fd, chunk_out, (size_t) out_len)
              != (ssize_t) out_len)
            {
              fprintf (stderr, _("%s: error: write failed: %s\n"),
                       prog, strerror (errno));
              goto cleanup;
            }

          if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL)
            break;
          /* A short read that was not FINAL is a truncated stream.  */
          if ((size_t) got < CHUNK_SIZE + CRYPTO_ABYTES)
            {
              fprintf (stderr, _("%s: error: stream truncation detected\n"), prog);
              goto cleanup;
            }
        }
    }

  fprintf (stderr, _("%s: file successfully decrypted\n"), prog);
  res = 1;

cleanup:
  secure_free (chunk_in);
  secure_free (chunk_out);
  secure_free (key);
  sodium_memzero (&state, sizeof (state));
  if (in_fd != -1 && !in_is_pipe)
    close (in_fd);
  if (out_fd != -1 && out_is_file)
    {
      if (res && fsync (out_fd) != 0)
        {
          fprintf (stderr, _("%s: error: fsync failed: %s\n"),
                   prog, strerror (errno));
          res = 0;
        }
      close (out_fd);
    }
  if (out_is_file && res && tmp_path)
    {
      if (rename (tmp_path, out_path) != 0)
        {
          fprintf (stderr, _("%s: error: cannot rename temporary file: %s\n"),
                   prog, strerror (errno));
          unlink (tmp_path);
          res = 0;
        }
      else if (fsync_dir (out_path) != 0)
        {
          fprintf (stderr, _("%s: warning: failed to sync parent directory: %s\n"),
                   prog, strerror (errno));
        }
    }
  else if (out_is_file && tmp_path)
    {
      unlink (tmp_path);
    }
  free (tmp_path);
  return res;
}
