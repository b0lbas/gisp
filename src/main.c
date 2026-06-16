/* src/main.c -- gisp file encryption/decryption utility.

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
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gisp.h"

static int
parse_ull (const char *str, unsigned long long *out)
{
  if (!str || *str == '\0')
    return -1;
  char *endptr;
  errno = 0;
  unsigned long long val = strtoull (str, &endptr, 10);
  if (errno == ERANGE || *endptr != '\0' || endptr == str)
    return -1;
  *out = val;
  return 0;
}

static void
print_usage (const char *prog)
{
  fprintf (stdout,
    "Usage: %s [OPTIONS]\n"
    "\n"
    "Options:\n"
    "  -e, --encrypt <file>   Encrypt FILE and write a gisp container\n"
    "  -d, --decrypt <vault>  Decrypt a gisp container\n"
    "  -o, --output  <file>   Destination path for the output file\n"
    "  -p, --opslimit <num>   Argon2id CPU ops limit (default: moderate)\n"
    "  -m, --memlimit <bytes> Argon2id memory limit in bytes (default: moderate)\n"
    "  -h, --help             Display this help and exit\n"
    "  -v, --version          Display version information and exit\n"
    "\n"
    "Report bugs to: <cmrtumilovic@gmail.com>\n"
    "Full documentation at: <https://github.com/b0lbas/gisp>\n",
    prog);
}

int
main (int argc, char *argv[])
{
  const char *prog = argv[0];

  if (sodium_init () == -1)
    {
      fprintf (stderr, "%s: fatal: libsodium initialisation failed\n", prog);
      return 1;
    }

  if (terminal_init_signals (prog) != 0)
    return 1;

  const char *mode     = NULL;
  const char *file_src = NULL;
  const char *file_dst = NULL;

  unsigned long long opslimit = crypto_pwhash_opslimit_moderate ();
  unsigned long long memlimit = crypto_pwhash_memlimit_moderate ();

  static const struct option long_options[] = {
    { "encrypt",  required_argument, 0, 'e' },
    { "decrypt",  required_argument, 0, 'd' },
    { "output",   required_argument, 0, 'o' },
    { "opslimit", required_argument, 0, 'p' },
    { "memlimit", required_argument, 0, 'm' },
    { "help",     no_argument,       0, 'h' },
    { "version",  no_argument,       0, 'v' },
    { 0, 0, 0, 0 }
  };

  int opt;
  int option_index = 0;
  while ((opt = getopt_long (argc, argv, "e:d:o:p:m:hv",
                             long_options, &option_index)) != -1)
    {
      switch (opt)
        {
        case 'e':
          mode     = "-e";
          file_src = optarg;
          break;
        case 'd':
          mode     = "-d";
          file_src = optarg;
          break;
        case 'o':
          file_dst = optarg;
          break;
        case 'p':
          {
            unsigned long long v;
            if (parse_ull (optarg, &v) != 0)
              {
                fprintf (stderr, "%s: invalid opslimit value: '%s'\n",
                         prog, optarg);
                return 1;
              }
            if (v < crypto_pwhash_opslimit_min ())
              v = crypto_pwhash_opslimit_min ();
            opslimit = v;
          }
          break;
        case 'm':
          {
            unsigned long long v;
            if (parse_ull (optarg, &v) != 0)
              {
                fprintf (stderr, "%s: invalid memlimit value: '%s'\n",
                         prog, optarg);
                return 1;
              }
            if (v < crypto_pwhash_memlimit_min ())
              v = crypto_pwhash_memlimit_min ();
            memlimit = v;
          }
          break;
        case 'h':
          print_usage (prog);
          return 0;
        case 'v':
          fprintf (stdout, "gisp v%d.0 (libsodium hardened)\n",
                   VAULT_VERSION);
          return 0;
        default:
          fprintf (stderr, "%s: try '--help' for usage information\n", prog);
          return 1;
        }
    }

  if (optind < argc || !mode || !file_src || !file_dst)
    {
      fprintf (stderr, "%s: error: missing or unexpected arguments\n", prog);
      print_usage (prog);
      return 1;
    }

  char *pass_buf = secure_malloc (MAX_PASS_LEN);
  if (!pass_buf)
    {
      fprintf (stderr, "%s: fatal: secure memory allocation failed\n", prog);
      return 1;
    }

  ssize_t p_len = get_password_secure ("Enter master password: ", pass_buf, MAX_PASS_LEN);

  if (p_len < MIN_PASS_LEN)
    {
      if (p_len >= 0)
        fprintf (stderr, "%s: error: password must be at least %d characters\n",
                 prog, MIN_PASS_LEN);
      secure_free (pass_buf);
      return 1;
    }

  if (strcmp (mode, "-e") == 0)
    {
      char *confirm_buf = secure_malloc (MAX_PASS_LEN);
      if (!confirm_buf)
        {
          fprintf (stderr, "%s: fatal: secure memory allocation failed\n", prog);
          secure_free (pass_buf);
          return 1;
        }
      ssize_t c_len = get_password_secure ("Confirm password: ", confirm_buf, MAX_PASS_LEN);
      int mismatch = (c_len != p_len)
                     || (sodium_memcmp ((const unsigned char *) pass_buf,
                                        (const unsigned char *) confirm_buf,
                                        MAX_PASS_LEN) != 0);
      secure_free (confirm_buf);
      if (mismatch)
        {
          fprintf (stderr, "%s: error: passwords do not match\n", prog);
          secure_free (pass_buf);
          return 1;
        }
    }

  int success = 0;
  if (strcmp (mode, "-e") == 0)
    success = encrypt_file (prog, file_src, file_dst, pass_buf,
                            (size_t) p_len, opslimit, memlimit);
  else if (strcmp (mode, "-d") == 0)
    success = decrypt_file (prog, file_src, file_dst, pass_buf,
                            (size_t) p_len);

  secure_free (pass_buf);
  return success ? 0 : 1;
}
