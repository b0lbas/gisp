/* test_core.c -- security and functional test suite for gisp.

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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sodium.h>
#include "gisp.h"

#define TEST_PASS "testpassword123"
#define TEST_PROG "gisp-test"

/* ---------------------------------------------------------------------------
   Test utilities.
   --------------------------------------------------------------------------- */

static void
create_dummy_file (const char *path, size_t size)
{
  int fd = open (path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  assert (fd != -1);
  if (size > 0)
    {
      unsigned char *buf = malloc (size);
      assert (buf);
      randombytes_buf (buf, size);
      ssize_t n = write (fd, buf, size);
      assert (n == (ssize_t) size);
      free (buf);
    }
  close (fd);
}

static int
compare_files (const char *path1, const char *path2)
{
  struct stat st1, st2;
  if (stat (path1, &st1) != 0 || stat (path2, &st2) != 0)
    return 0;
  if (st1.st_size != st2.st_size)
    return 0;
  int fd1 = open (path1, O_RDONLY);
  int fd2 = open (path2, O_RDONLY);
  assert (fd1 != -1 && fd2 != -1);
  unsigned char b1, b2;
  int res = 1;
  while (read (fd1, &b1, 1) == 1 && read (fd2, &b2, 1) == 1)
    {
      if (b1 != b2)
        {
          res = 0;
          break;
        }
    }
  close (fd1);
  close (fd2);
  return res;
}

/* ---------------------------------------------------------------------------
   Functional tests.
   --------------------------------------------------------------------------- */

static void
test_roundtrip (size_t size)
{
  printf ("Testing round-trip (size %zu)... ", size);
  create_dummy_file ("plain.tmp", size);
  int res = encrypt_file (TEST_PROG, "plain.tmp", "vault.tmp",
                         TEST_PASS, strlen (TEST_PASS),
                         crypto_pwhash_opslimit_min (),
                         crypto_pwhash_memlimit_min ());
  assert (res == 1);
  res = decrypt_file (TEST_PROG, "vault.tmp", "decrypted.tmp",
                     TEST_PASS, strlen (TEST_PASS));
  assert (res == 1);
  assert (compare_files ("plain.tmp", "decrypted.tmp"));
  printf ("OK\n");
  unlink ("plain.tmp");
  unlink ("vault.tmp");
  unlink ("decrypted.tmp");
}

/* ---------------------------------------------------------------------------
   Security & Integrity tests.
   --------------------------------------------------------------------------- */

static void
test_tamper (const char *name, size_t offset)
{
  printf ("Testing tampering (%s at offset %zu)... ", name, offset);
  create_dummy_file ("plain.tmp", 1024);
  encrypt_file (TEST_PROG, "plain.tmp", "vault.tmp",
                TEST_PASS, strlen (TEST_PASS),
                crypto_pwhash_opslimit_min (),
                crypto_pwhash_memlimit_min ());
  int fd = open ("vault.tmp", O_RDWR);
  assert (fd != -1);
  unsigned char b;
  lseek (fd, offset, SEEK_SET);
  read (fd, &b, 1);
  b ^= 0xFF;
  lseek (fd, offset, SEEK_SET);
  write (fd, &b, 1);
  close (fd);
  int res = decrypt_file (TEST_PROG, "vault.tmp", "decrypted.tmp",
                         TEST_PASS, strlen (TEST_PASS));
  assert (res == 0);
  printf ("OK\n");
  unlink ("plain.tmp");
  unlink ("vault.tmp");
  unlink ("decrypted.tmp");
}

static void
test_truncation (void)
{
  printf ("Testing stream truncation... ");
  create_dummy_file ("plain.tmp", 1024);
  encrypt_file (TEST_PROG, "plain.tmp", "vault.tmp",
                TEST_PASS, strlen (TEST_PASS),
                crypto_pwhash_opslimit_min (),
                crypto_pwhash_memlimit_min ());
  struct stat st;
  stat ("vault.tmp", &st);
  truncate ("vault.tmp", st.st_size - 1);
  int res = decrypt_file (TEST_PROG, "vault.tmp", "decrypted.tmp",
                         TEST_PASS, strlen (TEST_PASS));
  assert (res == 0);
  printf ("OK\n");
  unlink ("plain.tmp");
  unlink ("vault.tmp");
  unlink ("decrypted.tmp");
}

static void
test_memlimit_dos (void)
{
  printf ("Testing memlimit DoS protection... ");
  create_dummy_file ("plain.tmp", 16);
  encrypt_file (TEST_PROG, "plain.tmp", "vault.tmp",
                TEST_PASS, strlen (TEST_PASS),
                crypto_pwhash_opslimit_min (),
                crypto_pwhash_memlimit_min ());
  int fd = open ("vault.tmp", O_RDWR);
  assert (fd != -1);
  uint64_t bad_limit = MAX_ALLOWED_MEMLIMIT + 1;
  unsigned char buf[8];
  for (int i = 0; i < 8; i++)
    buf[i] = (bad_limit >> (i * 8)) & 0xFF;
  lseek (fd, 14, SEEK_SET);
  write (fd, buf, 8);
  close (fd);
  int res = decrypt_file (TEST_PROG, "vault.tmp", "decrypted.tmp",
                         TEST_PASS, strlen (TEST_PASS));
  assert (res == 0);
  printf ("OK\n");
  unlink ("plain.tmp");
  unlink ("vault.tmp");
  unlink ("decrypted.tmp");
}

static void
test_opslimit_dos (void)
{
  printf ("Testing opslimit DoS protection... ");
  create_dummy_file ("plain.tmp", 16);
  encrypt_file (TEST_PROG, "plain.tmp", "vault.tmp",
                TEST_PASS, strlen (TEST_PASS),
                crypto_pwhash_opslimit_min (),
                crypto_pwhash_memlimit_min ());
  int fd = open ("vault.tmp", O_RDWR);
  assert (fd != -1);
  uint64_t bad_limit = MAX_ALLOWED_OPSLIMIT + 1;
  unsigned char buf[8];
  for (int i = 0; i < 8; i++)
    buf[i] = (bad_limit >> (i * 8)) & 0xFF;
  lseek (fd, 6, SEEK_SET);
  write (fd, buf, 8);
  close (fd);
  int res = decrypt_file (TEST_PROG, "vault.tmp", "decrypted.tmp",
                         TEST_PASS, strlen (TEST_PASS));
  assert (res == 0);
  printf ("OK\n");
  unlink ("plain.tmp");
  unlink ("vault.tmp");
  unlink ("decrypted.tmp");
}

static void
test_wrong_password (void)
{
  printf ("Testing wrong password... ");
  create_dummy_file ("plain.tmp", 16);
  encrypt_file (TEST_PROG, "plain.tmp", "vault.tmp",
                TEST_PASS, strlen (TEST_PASS),
                crypto_pwhash_opslimit_min (),
                crypto_pwhash_memlimit_min ());
  int res = decrypt_file (TEST_PROG, "vault.tmp", "decrypted.tmp",
                         "wrongpassword", 13);
  assert (res == 0);
  printf ("OK\n");
  unlink ("plain.tmp");
  unlink ("vault.tmp");
  unlink ("decrypted.tmp");
}

static void
test_symlink_attack (void)
{
  printf ("Testing symlink attack prevention... ");
  create_dummy_file ("plain.tmp", 16);
  create_dummy_file ("target.tmp", 16);
  symlink ("target.tmp", "vault.tmp.tmp");
  int res = encrypt_file (TEST_PROG, "plain.tmp", "vault.tmp",
                         TEST_PASS, strlen (TEST_PASS),
                         crypto_pwhash_opslimit_min (),
                         crypto_pwhash_memlimit_min ());
  assert (res == 0);
  struct stat st;
  stat ("target.tmp", &st);
  assert (st.st_size == 16);
  printf ("OK\n");
  unlink ("plain.tmp");
  unlink ("target.tmp");
  unlink ("vault.tmp.tmp");
}

static void
test_early_tag_final (void)
{
  printf ("Testing early TAG_FINAL detection... ");
  size_t size = CHUNK_SIZE * 2;
  create_dummy_file ("plain.tmp", size);
  encrypt_file (TEST_PROG, "plain.tmp", "vault.tmp",
                TEST_PASS, strlen (TEST_PASS),
                crypto_pwhash_opslimit_min (),
                crypto_pwhash_memlimit_min ());
  truncate ("vault.tmp", HEADER_TOTAL_SIZE + CHUNK_SIZE + CRYPTO_ABYTES);
  int res = decrypt_file (TEST_PROG, "vault.tmp", "decrypted.tmp",
                         TEST_PASS, strlen (TEST_PASS));
  assert (res == 0);
  printf ("OK\n");
  unlink ("plain.tmp");
  unlink ("vault.tmp");
  unlink ("decrypted.tmp");
}

static void
test_file_permissions (void)
{
  printf ("Testing file permissions (0600)... ");
  create_dummy_file ("plain.tmp", 16);
  encrypt_file (TEST_PROG, "plain.tmp", "vault.tmp",
                TEST_PASS, strlen (TEST_PASS),
                crypto_pwhash_opslimit_min (),
                crypto_pwhash_memlimit_min ());
  struct stat st;
  stat ("vault.tmp", &st);
  assert ((st.st_mode & 0777) == 0600);
  decrypt_file (TEST_PROG, "vault.tmp", "decrypted.tmp",
                TEST_PASS, strlen (TEST_PASS));
  stat ("decrypted.tmp", &st);
  assert ((st.st_mode & 0777) == 0600);
  printf ("OK\n");
  unlink ("plain.tmp");
  unlink ("vault.tmp");
  unlink ("decrypted.tmp");
}

static void
test_partial_header (void)
{
  printf ("Testing partial header... ");
  create_dummy_file ("vault.tmp", HEADER_TOTAL_SIZE - 1);
  int res = decrypt_file (TEST_PROG, "vault.tmp", "decrypted.tmp",
                         TEST_PASS, strlen (TEST_PASS));
  assert (res == 0);
  printf ("OK\n");
  unlink ("vault.tmp");
}

static void
test_same_file (void)
{
  printf ("Testing same input/output error... ");
  create_dummy_file ("plain.tmp", 16);
  int res = encrypt_file (TEST_PROG, "plain.tmp", "plain.tmp",
                         TEST_PASS, strlen (TEST_PASS),
                         crypto_pwhash_opslimit_min (),
                         crypto_pwhash_memlimit_min ());
  assert (res == 0);
  printf ("OK\n");
  unlink ("plain.tmp");
}

static void
test_read_password_fd (void)
{
  printf ("Testing read_password_fd (line + newline strip)... ");
  int fds[2];
  assert (pipe (fds) == 0);
  const char *line = "hunter2pass\nextra";
  assert (write (fds[1], line, strlen (line)) == (ssize_t) strlen (line));
  close (fds[1]);
  char buf[256];
  ssize_t n = read_password_fd (fds[0], buf, sizeof buf);
  close (fds[0]);
  assert (n == 11);
  assert (strcmp (buf, "hunter2pass") == 0);
  printf ("OK\n");

  printf ("Testing read_password_fd (empty input)... ");
  assert (pipe (fds) == 0);
  close (fds[1]);              /* immediate EOF */
  n = read_password_fd (fds[0], buf, sizeof buf);
  close (fds[0]);
  assert (n == 0 && buf[0] == '\0');
  printf ("OK\n");
}

static void
test_configurable_ceiling (void)
{
  printf ("Testing configurable operator ceiling... ");
  create_dummy_file ("plain.tmp", 64);
  int res = encrypt_file (TEST_PROG, "plain.tmp", "vault.tmp",
                         TEST_PASS, strlen (TEST_PASS),
                         crypto_pwhash_opslimit_min (),
                         crypto_pwhash_memlimit_min ());
  assert (res == 1);

  /* Lower the memory ceiling below the container's memlimit: decrypt must
     reject it even though the password is correct.  */
  gisp_set_limits (0, 1024, 0);
  res = decrypt_file (TEST_PROG, "vault.tmp", "decrypted.tmp",
                     TEST_PASS, strlen (TEST_PASS));
  assert (res == 0);

  /* Restore the defaults; the very same container now decrypts cleanly.  */
  gisp_set_limits (MAX_ALLOWED_OPSLIMIT, MAX_ALLOWED_MEMLIMIT, MAX_VAULT_FILE_SIZE);
  res = decrypt_file (TEST_PROG, "vault.tmp", "decrypted.tmp",
                     TEST_PASS, strlen (TEST_PASS));
  assert (res == 1);
  assert (compare_files ("plain.tmp", "decrypted.tmp"));
  printf ("OK\n");
  unlink ("plain.tmp");
  unlink ("vault.tmp");
  unlink ("decrypted.tmp");
}

int
main (void)
{
  if (sodium_init () == -1)
    return 1;
  printf ("Running gisp security and functional test suite...\n\n");
  test_roundtrip (0);
  test_roundtrip (1);
  test_roundtrip (CHUNK_SIZE);
  test_roundtrip (CHUNK_SIZE + 1);
  test_roundtrip (CHUNK_SIZE * 2 + 123);
  test_tamper ("Magic", 0);
  test_tamper ("Version", 4);
  test_tamper ("Salt", 22);
  test_tamper ("PayloadLen", 38);
  test_tamper ("Ciphertext", HEADER_TOTAL_SIZE + 1);
  test_truncation ();
  test_memlimit_dos ();
  test_opslimit_dos ();
  test_wrong_password ();
  test_symlink_attack ();
  test_early_tag_final ();
  test_file_permissions ();
  test_partial_header ();
  test_same_file ();
  test_read_password_fd ();
  test_configurable_ceiling ();
  printf ("\nAll tests passed successfully!\n");
  return 0;
}
