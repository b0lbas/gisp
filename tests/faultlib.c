/* tests/faultlib.c -- syscall fault-injection shim for coverage of error paths.

   Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>
   Distributed under the GNU General Public License v3 or later; NO WARRANTY.

   Built as a shared object and LD_PRELOAD'ed in front of gisp to force the
   I/O failures that ordinary tests never hit (write/read/fsync/rename ...).

       GISP_FAIL=<name>    fail calls to that function
       GISP_FAIL_SKIP=<n>  let the first n matching calls succeed, fail the rest

   Build: cc -shared -fPIC -D_GNU_SOURCE faultlib.c -o faultlib.so -ldl  */

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *g_fail;
static long        g_skip;
static long        g_seen;

__attribute__((constructor))
static void
faultlib_init (void)
{
  g_fail = getenv ("GISP_FAIL");
  const char *s = getenv ("GISP_FAIL_SKIP");
  g_skip = s ? atol (s) : 0;
}

/* Return non-zero when a call to NAME should be made to fail.  */
static int
should_fail (const char *name)
{
  if (!g_fail || strcmp (g_fail, name) != 0)
    return 0;
  if (g_seen++ < g_skip)
    return 0;
  return 1;
}

ssize_t
write (int fd, const void *buf, size_t n)
{
  static ssize_t (*real) (int, const void *, size_t);
  if (!real)
    real = dlsym (RTLD_NEXT, "write");
  if (should_fail ("write"))
    {
      errno = EIO;
      return -1;
    }
  return real (fd, buf, n);
}

ssize_t
read (int fd, void *buf, size_t n)
{
  static ssize_t (*real) (int, void *, size_t);
  if (!real)
    real = dlsym (RTLD_NEXT, "read");
  if (should_fail ("read"))
    {
      errno = EIO;
      return -1;
    }
  return real (fd, buf, n);
}

int
fsync (int fd)
{
  static int (*real) (int);
  if (!real)
    real = dlsym (RTLD_NEXT, "fsync");
  if (should_fail ("fsync"))
    {
      errno = EIO;
      return -1;
    }
  return real (fd);
}

int
rename (const char *o, const char *n)
{
  static int (*real) (const char *, const char *);
  if (!real)
    real = dlsym (RTLD_NEXT, "rename");
  if (should_fail ("rename"))
    {
      errno = EACCES;
      return -1;
    }
  return real (o, n);
}
