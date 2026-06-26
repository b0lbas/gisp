/* fuzz/fuzz_password.c -- harness for read_password_fd().

   Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>
   Distributed under the GNU General Public License v3 or later; NO WARRANTY.

   read_password_fd() consumes untrusted bytes from a descriptor (a
   --passphrase-fd or --passphrase-file source), so it is fed arbitrary
   content here under ASan/UBSan to confirm the line handling and length
   bookkeeping never overrun the buffer.

   Build:
     clang -fsanitize=fuzzer,address,undefined -g -O1 -Iinclude \
       src/common.c src/terminal.c fuzz/fuzz_password.c -o fuzz_password -lsodium  */

#include <unistd.h>

#include "gisp.h"

int
LLVMFuzzerTestOneInput (const unsigned char *data, size_t size)
{
  int fds[2];
  if (pipe (fds) != 0)
    return 0;

  /* Stay below the pipe capacity so the single write never blocks.  */
  size_t n = size > 60000 ? 60000 : size;
  if (write (fds[1], data, n) < 0)
    {
      close (fds[0]); close (fds[1]);
      return 0;
    }
  close (fds[1]);

  char buf[MAX_PASS_LEN];
  read_password_fd (fds[0], buf, sizeof buf, NULL);
  close (fds[0]);
  return 0;
}
