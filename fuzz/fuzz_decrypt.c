/* fuzz/fuzz_decrypt.c -- libFuzzer harness for the gisp container parser.

   Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>
   Distributed under the GNU General Public License v3 or later; NO WARRANTY.

   The decryption path is the only place gisp consumes untrusted input, so it
   is the target that matters.  Each fuzzer input is treated as a candidate
   container and fed to decrypt_file().  Random data is rejected cheaply at the
   magic/version/parameter checks, before the slow KDF; seeding the corpus with
   a valid container (built with the matching passphrase and minimal KDF cost)
   lets mutations reach the key derivation and chunk-processing code too.

   Build:
     clang -fsanitize=fuzzer,address,undefined -g -O1 -Iinclude \
       src/common.c src/crypto.c src/terminal.c fuzz/fuzz_decrypt.c \
       -o fuzz_decrypt -lsodium
   Run:
     ./fuzz_decrypt corpus -dict=fuzz/gisp.dict -close_fd_mask=2  */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE            /* for mkdtemp */
#endif

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "gisp.h"

#define FUZZ_PASS "testpassword123"

/* The working files live inside a private 0700 directory created at startup,
   not at a fixed path in a world-writable place like /dev/shm.  A predictable
   name there invites a symlink race (CWE-377 / SonarCloud S5443); mkdtemp gives
   us an unguessable, owner-only directory in which fixed child names are safe.  */
static char g_dir[64];
static char IN_PATH[128];
static char OUT_PATH[128];

static int
make_workdir (void)
{
  /* Prefer tmpfs for speed, then $TMPDIR, then /tmp.  */
  const char *bases[] = { "/dev/shm", getenv ("TMPDIR"), "/tmp" };
  for (size_t i = 0; i < sizeof bases / sizeof bases[0]; i++)
    {
      if (!bases[i] || !bases[i][0])
        continue;
      snprintf (g_dir, sizeof g_dir, "%s/gispfuzz.XXXXXX", bases[i]);
      if (mkdtemp (g_dir))
        return 0;
    }
  return -1;
}

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void) argc;
  (void) argv;
  if (sodium_init () < 0)
    return -1;
  if (make_workdir () != 0)
    return -1;
  snprintf (IN_PATH,  sizeof IN_PATH,  "%s/in",  g_dir);
  snprintf (OUT_PATH, sizeof OUT_PATH, "%s/out", g_dir);
  /* Cap the memory ceiling well below the production 4 GiB so the fuzzer
     cannot trigger a legitimate multi-gigabyte Argon2id allocation and waste
     the budget (and trip the RSS limit) on the KDF instead of the parser.  */
  gisp_set_limits (0, 32UL * 1024 * 1024, 0);
  return 0;
}

int
LLVMFuzzerTestOneInput (const unsigned char *data, size_t size)
{
  int fd = open (IN_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0)
    return 0;
  if (write (fd, data, size) < 0)
    {
      close (fd);
      return 0;
    }
  close (fd);

  /* Clear any leftover output so the O_EXCL temp-file creation succeeds.  */
  char tmp[256];
  snprintf (tmp, sizeof tmp, "%s.tmp", OUT_PATH);
  unlink (OUT_PATH);
  unlink (tmp);

  decrypt_file ("fuzz", IN_PATH, OUT_PATH, FUZZ_PASS, strlen (FUZZ_PASS));
  return 0;
}
