/* fuzz/fuzz_roundtrip.c -- property fuzzer: decrypt(encrypt(x)) == x.

   Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>
   Distributed under the GNU General Public License v3 or later; NO WARRANTY.

   Treats each fuzzer input as plaintext, encrypts it, decrypts the result, and
   asserts the output is byte-identical.  This checks correctness of the whole
   encode/decode round trip (chunking, the FINAL tag, the streamed/fixed paths)
   rather than just crash-freedom: any asymmetry traps and is reported.

   Build:
     clang -fsanitize=fuzzer,address,undefined -g -O1 -Iinclude \
       src/common.c src/crypto.c src/terminal.c fuzz/fuzz_roundtrip.c \
       -o fuzz_roundtrip -lsodium  */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE            /* for mkdtemp */
#endif

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "gisp.h"

#define RT_PASS "fuzz-round-trip-passphrase"

/* Working files live in a private 0700 directory created at startup rather than
   at a fixed name in a world-writable place like /dev/shm, which would invite a
   symlink race (CWE-377 / SonarCloud S5443).  */
static char g_dir[64];
static char IN[128];
static char CT[128];
static char OUT[128];

static int
make_workdir (void)
{
  /* Prefer tmpfs for speed, then $TMPDIR, then /tmp.  */
  const char *bases[] = { "/dev/shm", getenv ("TMPDIR"), "/tmp" };
  for (size_t i = 0; i < sizeof bases / sizeof bases[0]; i++)
    {
      if (!bases[i] || !bases[i][0])
        continue;
      snprintf (g_dir, sizeof g_dir, "%s/gisprt.XXXXXX", bases[i]);
      if (mkdtemp (g_dir))
        return 0;
    }
  return -1;
}

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void) argc; (void) argv;
  if (sodium_init () < 0)
    return -1;
  if (make_workdir () != 0)
    return -1;
  snprintf (IN,  sizeof IN,  "%s/in",  g_dir);
  snprintf (CT,  sizeof CT,  "%s/ct",  g_dir);
  snprintf (OUT, sizeof OUT, "%s/out", g_dir);
  return 0;
}

static void
clear (const char *p)
{
  char t[256];
  snprintf (t, sizeof t, "%s.tmp", p);
  unlink (p);
  unlink (t);
}

int
LLVMFuzzerTestOneInput (const unsigned char *data, size_t size)
{
  if (size > 262144)            /* keep iterations fast */
    size = 262144;

  int fd = open (IN, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0)
    return 0;
  if (write (fd, data, size) < 0) { close (fd); return 0; }
  close (fd);
  clear (CT);
  clear (OUT);

  unsigned long long ops = crypto_pwhash_opslimit_min ();
  unsigned long long mem = crypto_pwhash_memlimit_min ();

  if (encrypt_file ("fuzz", IN, CT, RT_PASS, strlen (RT_PASS), ops, mem) != 1)
    return 0;                   /* encryption setup failure: not our concern */

  /* A container we just produced MUST decrypt with the same passphrase.  */
  if (decrypt_file ("fuzz", CT, OUT, RT_PASS, strlen (RT_PASS)) != 1)
    {
      fprintf (stderr, "round-trip: decrypt failed for %zu-byte input\n", size);
      __builtin_trap ();
    }

  /* ... and reproduce the original bytes exactly.  */
  fd = open (OUT, O_RDONLY);
  if (fd < 0)
    __builtin_trap ();
  unsigned char *buf = malloc (size ? size : 1);
  ssize_t n = read_all (fd, buf, size);
  unsigned char extra;
  ssize_t tail = read (fd, &extra, 1);
  close (fd);
  if (n != (ssize_t) size || tail != 0 || (size && memcmp (buf, data, size) != 0))
    {
      fprintf (stderr, "round-trip: output differs from input\n");
      __builtin_trap ();
    }
  free (buf);
  return 0;
}
