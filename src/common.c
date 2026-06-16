/* src/common.c -- gisp utility functions.

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
#include <sys/stat.h>

#include "gisp.h"

void *
secure_malloc (size_t size)
{
  if (size == 0)
    return NULL;

  void *ptr = sodium_malloc (size);
  if (!ptr)
    {
      static int warned = 0;
      if (!warned)
        {
          warned = 1;
          fprintf (stderr, "gisp: warning: secure memory allocation failed"
                           " (sodium_malloc returned NULL)\n");
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
  int fd = open (path, O_RDONLY);
  if (fd == -1)
    {
      fprintf (stderr, "%s: %s: cannot open file: %s\n",
               prog, path, strerror (errno));
      return -1;
    }
  struct stat st;
  if (fstat (fd, &st) != 0 || st.st_size < 0)
    {
      fprintf (stderr, "%s: %s: cannot stat file: %s\n",
               prog, path, strerror (errno));
      close (fd);
      return -1;
    }
  *out_size = (int64_t) st.st_size;
  return fd;
}

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
    }

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
