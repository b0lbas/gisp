/* src/main.c -- gisp file encryption/decryption utility.

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
#include <getopt.h>
#include <limits.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gisp.h"

/* Long-only options get values above the byte range so they never collide
   with a short option letter.  */
enum
{
  OPT_PASSPHRASE_FD = 256,
  OPT_PASSPHRASE_FILE,
  OPT_MAX_OPSLIMIT,
  OPT_MAX_MEMLIMIT,
  OPT_MAX_FILESIZE,
  OPT_MIN_PASSLEN,
  OPT_ALLOW_WEAK
};

static int
parse_ull (const char *str, unsigned long long *out)
{
  if (!str || *str == '\0')
    return -1;
  /* Reject a leading '-' by hand: strtoull silently negates and wraps it into
     a huge positive value, which would defeat the later limit checks.  */
  if (*str == '-')
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
print_usage (void)
{
  fprintf (stdout,
    _("Usage: %s [OPTIONS]\n"
      "\n"
      "Encrypt or decrypt a file with XChaCha20-Poly1305 and Argon2id.\n"
      "A path of '-' selects standard input or standard output.\n"
      "\n"
      "Mode:\n"
      "  -e, --encrypt <file>   Encrypt FILE and write a gisp container\n"
      "  -d, --decrypt <vault>  Decrypt a gisp container\n"
      "  -o, --output  <file>   Destination path for the output file\n"
      "\n"
      "Key derivation (encryption):\n"
      "  -p, --opslimit <num>   Argon2id CPU ops limit (default: moderate)\n"
      "  -m, --memlimit <bytes> Argon2id memory limit in bytes (default: moderate)\n"
      "\n"
      "Passphrase input (for non-interactive use):\n"
      "      --passphrase-fd <n>     Read the passphrase from file descriptor N\n"
      "      --passphrase-file <f>   Read the passphrase from file F\n"
      "\n"
      "Resource ceilings (protect the machine doing the work):\n"
      "      --max-opslimit <num>    Reject containers above this ops limit\n"
      "      --max-memlimit <bytes>  Reject containers above this memory limit\n"
      "      --max-filesize <bytes>  Reject plaintext larger than this\n"
      "      --min-password-length <n>  Required minimum passphrase length\n"
      "      --allow-weak-password   Permit a minimum below the recommended one\n"
      "\n"
      "  -h, --help             Display this help and exit\n"
      "  -v, --version          Display version information and exit\n"
      "\n"),
    PROGRAM_NAME);
  /* End --help with where to report bugs and find the project.  */
  fprintf (stdout,
    _("Report bugs to: <%s>\n"
      "gisp home page: <https://savannah.nongnu.org/projects/gisp>\n"),
    PACKAGE_BUGREPORT);
}

static void
print_version (void)
{
  /* "program version" banner.  */
  fprintf (stdout, "%s %s\n", PROGRAM_NAME, VERSION);
  fprintf (stdout, "Copyright (C) 2026 Uladzislau Bolbas\n");
  fprintf (stdout,
    _("License GPLv3+: GNU GPL version 3 or later"
      " <https://gnu.org/licenses/gpl.html>.\n"
      "This is free software: you are free to change and redistribute it.\n"
      "There is NO WARRANTY, to the extent permitted by law.\n"));
  fprintf (stdout, "\n");
  fprintf (stdout, _("Written by Uladzislau Bolbas.\n"));
}

int
main (int argc, char *argv[])
{
  /* Set up message translation before any user-facing string is produced.  */
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  /* Nothing cryptographic is safe before this returns, so do it first.  */
  if (sodium_init () == -1)
    {
      fprintf (stderr, _("%s: fatal: libsodium initialisation failed\n"),
               PROGRAM_NAME);
      return 1;
    }

  /* Install handlers before touching the terminal so an interrupt during the
     password prompt can always restore the echo flag.  */
  if (terminal_init_signals () != 0)
    return 1;

  const char *mode     = NULL;
  const char *file_src = NULL;
  const char *file_dst = NULL;

  unsigned long long opslimit = crypto_pwhash_opslimit_moderate ();
  unsigned long long memlimit = crypto_pwhash_memlimit_moderate ();

  /* Operator-side ceilings default to the compiled maxima; the user may move
     them (see the two-class limit model documented in the manual).  */
  unsigned long long max_opslimit = MAX_ALLOWED_OPSLIMIT;
  unsigned long long max_memlimit = MAX_ALLOWED_MEMLIMIT;
  uint64_t           max_filesize = MAX_VAULT_FILE_SIZE;

  unsigned long long min_pass_len = MIN_PASS_LEN;
  int                allow_weak   = 0;

  int   pass_fd   = -1;     /* < 0 means read interactively from the tty.  */
  const char *pass_file = NULL;

  static const struct option long_options[] = {
    { "encrypt",             required_argument, 0, 'e' },
    { "decrypt",             required_argument, 0, 'd' },
    { "output",              required_argument, 0, 'o' },
    { "opslimit",            required_argument, 0, 'p' },
    { "memlimit",            required_argument, 0, 'm' },
    { "passphrase-fd",       required_argument, 0, OPT_PASSPHRASE_FD },
    { "passphrase-file",     required_argument, 0, OPT_PASSPHRASE_FILE },
    { "max-opslimit",        required_argument, 0, OPT_MAX_OPSLIMIT },
    { "max-memlimit",        required_argument, 0, OPT_MAX_MEMLIMIT },
    { "max-filesize",        required_argument, 0, OPT_MAX_FILESIZE },
    { "min-password-length", required_argument, 0, OPT_MIN_PASSLEN },
    { "allow-weak-password", no_argument,       0, OPT_ALLOW_WEAK },
    { "help",                no_argument,       0, 'h' },
    { "version",             no_argument,       0, 'v' },
    { 0, 0, 0, 0 }
  };

  int opt;
  int option_index = 0;
  while ((opt = getopt_long (argc, argv, "e:d:o:p:m:hv",
                             long_options, &option_index)) != -1)
    {
      unsigned long long v;
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
          if (parse_ull (optarg, &v) != 0)
            {
              fprintf (stderr, _("%s: invalid opslimit value: '%s'\n"),
                       PROGRAM_NAME, optarg);
              return 1;
            }
          /* Clamp up to libsodium's floor: a too-weak value is the user's
             mistake, not a reason to abort.  */
          if (v < crypto_pwhash_opslimit_min ())
            v = crypto_pwhash_opslimit_min ();
          opslimit = v;
          break;
        case 'm':
          if (parse_ull (optarg, &v) != 0)
            {
              fprintf (stderr, _("%s: invalid memlimit value: '%s'\n"),
                       PROGRAM_NAME, optarg);
              return 1;
            }
          if (v < crypto_pwhash_memlimit_min ())
            v = crypto_pwhash_memlimit_min ();
          memlimit = v;
          break;
        case OPT_PASSPHRASE_FD:
          if (parse_ull (optarg, &v) != 0 || v > (unsigned long long) INT_MAX)
            {
              fprintf (stderr, _("%s: invalid file descriptor: '%s'\n"),
                       PROGRAM_NAME, optarg);
              return 1;
            }
          pass_fd = (int) v;
          break;
        case OPT_PASSPHRASE_FILE:
          pass_file = optarg;
          break;
        case OPT_MAX_OPSLIMIT:
          if (parse_ull (optarg, &v) != 0)
            {
              fprintf (stderr, _("%s: invalid max-opslimit value: '%s'\n"),
                       PROGRAM_NAME, optarg);
              return 1;
            }
          max_opslimit = v;
          break;
        case OPT_MAX_MEMLIMIT:
          if (parse_ull (optarg, &v) != 0)
            {
              fprintf (stderr, _("%s: invalid max-memlimit value: '%s'\n"),
                       PROGRAM_NAME, optarg);
              return 1;
            }
          max_memlimit = v;
          break;
        case OPT_MAX_FILESIZE:
          if (parse_ull (optarg, &v) != 0)
            {
              fprintf (stderr, _("%s: invalid max-filesize value: '%s'\n"),
                       PROGRAM_NAME, optarg);
              return 1;
            }
          max_filesize = v;
          break;
        case OPT_MIN_PASSLEN:
          if (parse_ull (optarg, &v) != 0 || v == 0)
            {
              fprintf (stderr, _("%s: invalid min-password-length value: '%s'\n"),
                       PROGRAM_NAME, optarg);
              return 1;
            }
          min_pass_len = v;
          break;
        case OPT_ALLOW_WEAK:
          allow_weak = 1;
          break;
        case 'h':
          print_usage ();
          return 0;
        case 'v':
          print_version ();
          return 0;
        default:
          fprintf (stderr, _("%s: try '--help' for usage information\n"),
                   PROGRAM_NAME);
          return 1;
        }
    }

  /* Reject leftover non-option arguments as well as missing ones, so a stray
     path can never be silently ignored.  */
  if (optind < argc || !mode || !file_src || !file_dst)
    {
      fprintf (stderr, _("%s: error: missing or unexpected arguments\n"),
               PROGRAM_NAME);
      print_usage ();
      return 1;
    }

  if (pass_fd >= 0 && pass_file)
    {
      fprintf (stderr,
               _("%s: error: --passphrase-fd and --passphrase-file are"
                 " mutually exclusive\n"), PROGRAM_NAME);
      return 1;
    }

  /* A passphrase fd must not be the same descriptor the ciphertext flows
     through, or the two reads would consume each other's bytes.  */
  if (pass_fd == STDIN_FILENO && is_stdio (file_src))
    {
      fprintf (stderr,
               _("%s: error: passphrase fd 0 conflicts with reading data from"
                 " standard input\n"), PROGRAM_NAME);
      return 1;
    }

  /* Lowering the minimum below the recommended value weakens security, so it
     needs an explicit opt-in; raising it is always allowed.  */
  if (min_pass_len < MIN_PASS_LEN && !allow_weak)
    {
      fprintf (stderr,
               _("%s: error: minimum password length %llu is below the"
                 " recommended %d; pass --allow-weak-password to permit it\n"),
               PROGRAM_NAME, min_pass_len, MIN_PASS_LEN);
      return 1;
    }
  if (min_pass_len > MAX_PASS_LEN - 1)
    min_pass_len = MAX_PASS_LEN - 1;

  /* Publish the operator ceilings to the crypto core.  */
  gisp_set_limits (max_opslimit, max_memlimit, max_filesize);

  /* A passphrase from an fd or file is non-interactive: no prompt, no echo
     handling, and no confirmation step is possible.  */
  int noninteractive = (pass_fd >= 0 || pass_file != NULL);

  if (strcmp (mode, "-e") == 0
      && (opslimit < crypto_pwhash_opslimit_moderate ()
          || memlimit < crypto_pwhash_memlimit_moderate ()))
    fprintf (stderr,
             _("%s: warning: using KDF parameters below the recommended level\n"),
             PROGRAM_NAME);

  /* Hold the password in guarded, mlocked memory so it never reaches swap and
     is wiped on free.  */
  char *pass_buf = secure_malloc (MAX_PASS_LEN);
  if (!pass_buf)
    {
      fprintf (stderr, _("%s: fatal: secure memory allocation failed\n"),
               PROGRAM_NAME);
      return 1;
    }

  ssize_t p_len;
  int p_truncated = 0;
  if (noninteractive)
    {
      int src_fd = pass_fd;
      int close_src = 0;
      if (pass_file)
        {
          src_fd = open (pass_file, O_RDONLY);
          if (src_fd == -1)
            {
              fprintf (stderr, _("%s: %s: cannot open passphrase file: %s\n"),
                       PROGRAM_NAME, pass_file, strerror (errno));
              secure_free (pass_buf);
              return 1;
            }
          close_src = 1;
        }
      p_len = read_password_fd (src_fd, pass_buf, MAX_PASS_LEN, &p_truncated);
      if (close_src)
        close (src_fd);
    }
  else
    {
      p_len = get_password_secure (_("Enter master password: "),
                                   pass_buf, MAX_PASS_LEN, &p_truncated);
    }

  if (p_len < (ssize_t) min_pass_len)
    {
      if (p_len >= 0)
        fprintf (stderr,
                 _("%s: error: password must be at least %llu characters\n"),
                 PROGRAM_NAME, min_pass_len);
      secure_free (pass_buf);
      return 1;
    }

  if (p_truncated)
    fprintf (stderr, _("%s: warning: password truncated to %d characters\n"),
             PROGRAM_NAME, MAX_PASS_LEN - 1);

  /* Confirm the passphrase only when we can ask twice -- i.e. interactively.  */
  if (!noninteractive && strcmp (mode, "-e") == 0)
    {
      char *confirm_buf = secure_malloc (MAX_PASS_LEN);
      if (!confirm_buf)
        {
          fprintf (stderr, _("%s: fatal: secure memory allocation failed\n"),
                   PROGRAM_NAME);
          secure_free (pass_buf);
          return 1;
        }
      ssize_t c_len = get_password_secure (_("Confirm password: "),
                                           confirm_buf, MAX_PASS_LEN, NULL);
      /* Compare in constant time over the whole buffer, not just the used
         length, so timing never reveals where two passwords first differ.  */
      int mismatch = (c_len != p_len)
                     || (sodium_memcmp ((const unsigned char *) pass_buf,
                                        (const unsigned char *) confirm_buf,
                                        MAX_PASS_LEN) != 0);
      secure_free (confirm_buf);
      if (mismatch)
        {
          fprintf (stderr, _("%s: error: passwords do not match\n"),
                   PROGRAM_NAME);
          secure_free (pass_buf);
          return 1;
        }
    }

  int success = 0;
  if (strcmp (mode, "-e") == 0)
    success = encrypt_file (PROGRAM_NAME, file_src, file_dst, pass_buf,
                            (size_t) p_len, opslimit, memlimit);
  else if (strcmp (mode, "-d") == 0)
    success = decrypt_file (PROGRAM_NAME, file_src, file_dst, pass_buf,
                            (size_t) p_len);

  secure_free (pass_buf);
  return success ? 0 : 1;
}
