/* src/common.c -- gisp utility functions.

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
#include <sys/stat.h>

#include "gisp.h"

/* A path of "-" selects a standard stream instead of a named file.  The NULL
   guard lets callers pass an unset path without a separate check.  */
int
is_stdio (const char *path)
{
  return path && path[0] == '-' && path[1] == '\0';
}

/* Allocate memory for secrets.  sodium_malloc surrounds the region with
   guard pages, locks it out of swap, and zeroes it on free, so keys and
   passwords cannot leak to disk or linger after use.  */
void *
secure_malloc (size_t size)
{
  if (size == 0)
    return NULL;

  void *ptr = sodium_malloc (size);
  if (!ptr)
    {
      /* Warn only once: a failing allocator would otherwise flood stderr.  */
      static int warned = 0;
      if (!warned)
        {
          warned = 1;
          fprintf (stderr, "%s: %s\n", PACKAGE,
                   _("warning: secure memory allocation failed"
                     " (sodium_malloc returned NULL)"));
        }
    }
  return ptr;
}

void
secure_free (void *ptr)
{
  if (ptr)
    sodium_free (ptr);
}

/* read() and write() may transfer fewer bytes than asked on pipes, signals,
   or large requests; these loop until the whole buffer is handled so callers
   can treat a short count as a real error.  */
ssize_t
read_all (int fd, unsigned char *buf, size_t size)
{
  size_t total = 0;
  while (total < size)
    {
      ssize_t n = read (fd, buf + total, size - total);
      if (n < 0)
        return -1;
      if (n == 0)
        break;
      total += (size_t) n;
    }
  return (ssize_t) total;
}

ssize_t
write_all (int fd, const unsigned char *buf, size_t size)
{
  size_t total = 0;
  while (total < size)
    {
      ssize_t n = write (fd, buf + total, size - total);
      if (n <= 0)
        return -1;
      total += (size_t) n;
    }
  return (ssize_t) total;
}

/* The container format is fixed little-endian so a file written on one
   machine decrypts byte-for-byte on any other, regardless of host endianness.
   These helpers do the conversion explicitly instead of memcpy'ing the
   native layout.  */
void
serialize_uint16 (unsigned char *buf, uint16_t val)
{
  buf[0] = (unsigned char)  (val        & 0xFF);
  buf[1] = (unsigned char) ((val >> 8)  & 0xFF);
}

uint16_t
deserialize_uint16 (const unsigned char *buf)
{
  return (uint16_t) (buf[0] | ((uint16_t) buf[1] << 8));
}

void
serialize_uint64 (unsigned char *buf, uint64_t val)
{
  buf[0] = (unsigned char)  (val        & 0xFF);
  buf[1] = (unsigned char) ((val >>  8) & 0xFF);
  buf[2] = (unsigned char) ((val >> 16) & 0xFF);
  buf[3] = (unsigned char) ((val >> 24) & 0xFF);
  buf[4] = (unsigned char) ((val >> 32) & 0xFF);
  buf[5] = (unsigned char) ((val >> 40) & 0xFF);
  buf[6] = (unsigned char) ((val >> 48) & 0xFF);
  buf[7] = (unsigned char) ((val >> 56) & 0xFF);
}

uint64_t
deserialize_uint64 (const unsigned char *buf)
{
  return ((uint64_t) buf[0])
       | ((uint64_t) buf[1] <<  8)
       | ((uint64_t) buf[2] << 16)
       | ((uint64_t) buf[3] << 24)
       | ((uint64_t) buf[4] << 32)
       | ((uint64_t) buf[5] << 40)
       | ((uint64_t) buf[6] << 48)
       | ((uint64_t) buf[7] << 56);
}

/* Checked arithmetic used when validating sizes taken from an untrusted
   header.  An overflow there could otherwise wrap to a small number and
   pass a length check it should have failed.  */
int
u64_add_overflow (uint64_t a, uint64_t b, uint64_t *result)
{
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_add_overflow (a, b, result);
#else
  if (b > UINT64_MAX - a)
    return 1;
  *result = a + b;
  return 0;
#endif
}

int
u64_mul_overflow (uint64_t a, uint64_t b, uint64_t *result)
{
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_mul_overflow (a, b, result);
#else
  if (a != 0 && b > UINT64_MAX / a)
    return 1;
  *result = a * b;
  return 0;
#endif
}

int
container_size_for_payload (uint64_t payload_len, uint64_t *result)
{
  /* Overflow-safe ceiling division: computing (payload_len + CHUNK_SIZE - 1)
     would itself wrap for a payload_len within CHUNK_SIZE of UINT64_MAX and
     hide the overflow, so divide first.  An empty payload still yields one
     final chunk.  */
  uint64_t chunks = (payload_len == 0)
                    ? 1
                    : (payload_len / CHUNK_SIZE
                       + (payload_len % CHUNK_SIZE != 0));
  uint64_t total;
  if (u64_mul_overflow (chunks, (uint64_t) CRYPTO_ABYTES, &total)
      || u64_add_overflow (total, (uint64_t) HEADER_TOTAL_SIZE, &total)
      || u64_add_overflow (total, payload_len, &total))
    return 1;
  *result = total;
  return 0;
}

/* Decide whether an open fd and a path are the same file by comparing
   device and inode, not the path strings.  String comparison would miss
   symlinks, hard links, "./foo" vs "foo", and absolute vs relative forms,
   any of which would let us overwrite the input while still reading it.  */
int
check_same_file (int fd1, const char *path2)
{
  struct stat st1, st2;
  if (fstat (fd1, &st1) != 0)
    return 0;
  if (stat (path2, &st2) != 0)
    return 0;
  return (st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino) ? 1 : 0;
}

int
safely_open_input (const char *prog, const char *path, int64_t *out_size)
{
  /* O_NONBLOCK so the open itself cannot hang: a plain O_RDONLY open of a FIFO
     with no writer (or of some devices) blocks indefinitely, before we ever get
     to reject it below.  Regular files ignore the flag; we clear it afterwards
     regardless so subsequent reads keep ordinary blocking semantics.  */
  int fd = open (path, O_RDONLY | O_NONBLOCK);
  if (fd == -1)
    {
      fprintf (stderr, _("%s: %s: cannot open file: %s\n"),
               prog, path, strerror (errno));
      return -1;
    }
  struct stat st;
  if (fstat (fd, &st) != 0 || st.st_size < 0)
    {
      fprintf (stderr, _("%s: %s: cannot stat file: %s\n"),
               prog, path, strerror (errno));
      close (fd);
      return -1;
    }
  /* Only a regular file has a meaningful stattable length to drive the
     fixed-size code path.  A FIFO or device reports st_size 0, which would be
     silently treated as an empty input; reject it so the caller is told to use
     "-" for a real stream instead of producing a truncated container.  */
  if (!S_ISREG (st.st_mode))
    {
      fprintf (stderr,
               _("%s: %s: not a regular file (use '-' to read a stream)\n"),
               prog, path);
      close (fd);
      return -1;
    }
  int flags = fcntl (fd, F_GETFL);
  if (flags != -1)
    (void) fcntl (fd, F_SETFL, flags & ~O_NONBLOCK);
  *out_size = (int64_t) st.st_size;
  return fd;
}

/* fsync the directory that contains PATH.  A rename is only durable once the
   directory entry itself is flushed; without this a crash just after rename
   could leave the new name missing even though the data was synced.  */
int
fsync_dir (const char *path)
{
  char *dir_path = strdup (path);
  if (!dir_path)
    return -1;

  char *last_slash = strrchr (dir_path, '/');
  if (last_slash)
    {
      if (last_slash == dir_path)
        last_slash[1] = '\0';
      else
        *last_slash = '\0';
    }
  else
    {
      /* Current directory.  */
      free (dir_path);
      dir_path = strdup (".");
      if (!dir_path)
        return -1;
    }

  /* O_DIRECTORY guarantees we never fsync something that merely shares the
     directory's name (e.g. a symlink swapped in underneath us).  */
  int fd = open (dir_path, O_RDONLY | O_DIRECTORY);
  if (fd == -1)
    {
      free (dir_path);
      return -1;
    }

  int res = fsync (fd);
  close (fd);
  free (dir_path);
  return res;
}
