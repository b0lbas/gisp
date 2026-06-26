## src/Makefile.am -- build the gisp program.
##
## Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>
## Distributed under the GNU General Public License v3 or later; NO WARRANTY.

AM_CPPFLAGS = -I$(top_srcdir)/include -DLOCALEDIR=\"$(localedir)\" $(SODIUM_CFLAGS)
AM_CFLAGS = $(HARDENING_CFLAGS)
AM_LDFLAGS = $(HARDENING_LDFLAGS)

## Core modules (everything except main) go into a convenience library so the
## test suite can link the exact same objects the program uses.
noinst_LIBRARIES = libgispcore.a
libgispcore_a_SOURCES = common.c crypto.c terminal.c

bin_PROGRAMS = gisp
gisp_SOURCES = main.c
gisp_LDADD = libgispcore.a $(SODIUM_LIBS) $(LIBINTL)
