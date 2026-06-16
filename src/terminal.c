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

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>

#include "gisp.h"

static struct termios        g_old_termios;
static volatile sig_atomic_t g_tty_hidden = 0;
static volatile sig_atomic_t g_tty_fd     = -1;

static void
signal_handler (int sig)
{
  if (g_tty_hidden && g_tty_fd != -1)
    tcsetattr (g_tty_fd, TCSANOW, &g_old_termios);

  if (sig == SIGTSTP)
    {
      signal (SIGTSTP, SIG_DFL);
      raise (SIGSTOP);
    }
  else if (sig == SIGCONT)
    {
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
      fprintf (stderr, "%s: fatal: signal handler installation failed\n", PROGRAM_NAME);
      return -1;
    }
  return 0;
}

ssize_t
get_password_secure (const char *prompt, char *buf, size_t max_len)
{
  int tty_fd = open ("/dev/tty", O_RDWR);
  if (tty_fd == -1)
    return -1;

  if (tcgetattr (tty_fd, &g_old_termios) != 0)
    {
      close (tty_fd);
      return -1;
    }

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

  if (nread == 0)
    {
      sodium_memzero (buf, max_len);
      return -1;
    }

  return (ssize_t) nread;
}
