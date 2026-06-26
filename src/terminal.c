/* src/terminal.c -- gisp terminal and signal handling.

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
#include <signal.h>
#include <string.h>
#include <stdlib.h>

#include "gisp.h"

/* Shared with the signal handler, hence volatile sig_atomic_t: the handler
   must see the current terminal state to know whether echo needs restoring.  */
static struct termios        g_old_termios;
static volatile sig_atomic_t g_tty_hidden = 0;
static volatile sig_atomic_t g_tty_fd     = -1;

/* The whole point of this handler is to never leave the user's terminal with
   echo disabled.  If we are killed mid-prompt, restore the saved settings
   before doing anything else.  */
static void
signal_handler (int sig)
{
  if (g_tty_hidden && g_tty_fd != -1)
    tcsetattr (g_tty_fd, TCSANOW, &g_old_termios);

  if (sig == SIGTSTP)
    {
      /* Hand control back to the default action so the process actually
         stops; echo is already restored above, so the shell prompt behaves
         normally while we are suspended.  */
      signal (SIGTSTP, SIG_DFL);
      raise (SIGSTOP);
    }
  else if (sig == SIGCONT)
    {
      /* On resume, re-arm every handler: the SIGTSTP one was reset to default
         above, and a foreground shell may have reset the terminal while we
         were stopped, so we must re-hide echo if a prompt is still active.  */
      struct sigaction sa;
      sa.sa_handler = signal_handler;
      sigemptyset (&sa.sa_mask);
      sa.sa_flags = SA_RESTART;
#if defined(SA_RESTORER)
      sa.sa_restorer = NULL;
#endif
      (void) sigaction (SIGINT,  &sa, NULL);
      (void) sigaction (SIGTERM, &sa, NULL);
      (void) sigaction (SIGQUIT, &sa, NULL);
      (void) sigaction (SIGHUP,  &sa, NULL);
      (void) sigaction (SIGTSTP, &sa, NULL);
      (void) sigaction (SIGCONT, &sa, NULL);

      if (g_tty_hidden && g_tty_fd != -1)
        {
          struct termios noecho = g_old_termios;
          noecho.c_lflag &= ~(tcflag_t) ECHO;
          tcsetattr (g_tty_fd, TCSANOW, &noecho);
        }
    }
  else
    {
      /* For terminating signals, leave immediately with _exit: it is
         async-signal-safe, whereas exit() would run handlers and flush
         stdio buffers that may hold sensitive data.  */
      _exit (1);
    }
}

int
terminal_init_signals (void)
{
  struct sigaction sa;
  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = signal_handler;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = SA_RESTART;

  if (sigaction (SIGINT,  &sa, NULL) != 0
      || sigaction (SIGTERM, &sa, NULL) != 0
      || sigaction (SIGQUIT, &sa, NULL) != 0
      || sigaction (SIGHUP,  &sa, NULL) != 0
      || sigaction (SIGTSTP, &sa, NULL) != 0
      || sigaction (SIGCONT, &sa, NULL) != 0)
    {
      fprintf (stderr, _("%s: fatal: signal handler installation failed\n"),
               PROGRAM_NAME);
      return -1;
    }
  return 0;
}

ssize_t
read_password_fd (int fd, char *buf, size_t max_len)
{
  if (max_len == 0)
    return -1;

  /* Read one line, exactly like the interactive path but without any terminal
     handling: the source is a pipe or file, so there is no echo to suppress
     and no /dev/tty involved.  This is what makes non-interactive pipelines
     work.  */
  size_t nread = 0;
  while (nread < max_len - 1)
    {
      char c;
      ssize_t n = read (fd, &c, 1);
      if (n < 0)
        {
          if (errno == EINTR)
            continue;
          sodium_memzero (buf, max_len);
          return -1;
        }
      if (n == 0 || c == '\n' || c == '\r')
        break;
      buf[nread++] = c;
    }
  buf[nread] = '\0';

  return (ssize_t) nread;
}

ssize_t
get_password_secure (const char *prompt, char *buf, size_t max_len)
{
  /* Zero the whole buffer up front so the unused tail is deterministic.  The
     caller's constant-time confirmation compares the full buffer, not just the
     used length; this makes that comparison's correctness self-evident instead
     of relying on the allocator's fill pattern.  */
  sodium_memzero (buf, max_len);

  /* Read from the controlling terminal directly, not stdin: this still works
     when stdin is a pipe or redirected file, and guarantees the prompt and
     the typed password go to a real tty rather than into another program.  */
  int tty_fd = open ("/dev/tty", O_RDWR);
  if (tty_fd == -1)
    return -1;

  if (tcgetattr (tty_fd, &g_old_termios) != 0)
    {
      close (tty_fd);
      return -1;
    }

  /* Block all signals while we publish g_tty_fd/g_tty_hidden and flip echo
     off.  Otherwise a signal arriving mid-update could run the handler
     against half-set state and restore the wrong terminal settings.  */
  sigset_t full_mask, old_mask;
  sigfillset (&full_mask);
  if (sigprocmask (SIG_BLOCK, &full_mask, &old_mask) != 0)
    {
      close (tty_fd);
      return -1;
    }

  g_tty_fd     = tty_fd;
  g_tty_hidden = 1;

  struct termios noecho = g_old_termios;
  noecho.c_lflag &= ~(tcflag_t) ECHO;
  if (tcsetattr (tty_fd, TCSANOW, &noecho) != 0)
    {
      g_tty_hidden = 0;
      g_tty_fd     = -1;
      sigprocmask (SIG_SETMASK, &old_mask, NULL);
      close (tty_fd);
      return -1;
    }

  sigprocmask (SIG_SETMASK, &old_mask, NULL);

  (void) write (tty_fd, prompt, strlen (prompt));

  size_t nread = 0;
  while (nread < max_len - 1)
    {
      char c;
      ssize_t n = read (tty_fd, &c, 1);
      if (n < 0)
        {
          /* A signal merely interrupted the read; retry.  Any other error
             discards what was typed so a partial password is never used.  */
          if (errno == EINTR)
            continue;
          nread = 0;
          break;
        }
      if (n == 0 || c == '\n' || c == '\r')
        break;
      buf[nread++] = c;
    }
  buf[nread] = '\0';

  (void) write (tty_fd, "\n", 1);

  sigprocmask (SIG_BLOCK, &full_mask, &old_mask);
  tcsetattr (tty_fd, TCSANOW, &g_old_termios);
  g_tty_fd     = -1;
  g_tty_hidden = 0;
  sigprocmask (SIG_SETMASK, &old_mask, NULL);

  close (tty_fd);

  /* Wipe the buffer on the empty/error path so no fragment of a keystroke
     survives in memory for the caller to misuse.  */
  if (nread == 0)
    {
      sodium_memzero (buf, max_len);
      return -1;
    }

  return (ssize_t) nread;
}
