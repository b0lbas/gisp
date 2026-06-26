## tests/Makefile.am -- gisp functional and security test suite.
##
## Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>
## Distributed under the GNU General Public License v3 or later; NO WARRANTY.

AM_CPPFLAGS = -I$(top_srcdir)/include -DLOCALEDIR=\"$(localedir)\" $(SODIUM_CFLAGS)

check_PROGRAMS = test_runner
test_runner_SOURCES = test_core.c
test_runner_LDADD = $(top_builddir)/src/libgispcore.a $(SODIUM_LIBS) $(LIBINTL)

## Point the shell integration test at the freshly built binary.
AM_TESTS_ENVIRONMENT = GISP='$(abs_top_builddir)/src/gisp'; export GISP;

TESTS = test_runner test_cli.sh test_vectors.sh

## Shipped but not run by "make check": the portable shell tests and the
## pinned format vectors, plus the (Linux-only) fault-injection tooling that
## maintainers run under coverage.
EXTRA_DIST = \
	test_cli.sh \
	test_vectors.sh \
	test_faults.sh \
	faultlib.c \
	overflow_diff.c \
	vectors/passphrase \
	vectors/plaintext \
	vectors/v1_fixed.gisp \
	vectors/v1_streamed.gisp \
	vectors/v1_truncated.gisp
