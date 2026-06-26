## tests/Makefile.am -- gisp functional and security test suite.
##
## Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>
## Distributed under the GNU General Public License v3 or later; NO WARRANTY.

AM_CPPFLAGS = -I$(top_srcdir)/include -DLOCALEDIR=\"$(localedir)\" $(SODIUM_CFLAGS)

check_PROGRAMS = test_runner
test_runner_SOURCES = test_core.c
test_runner_LDADD = $(top_builddir)/src/libgispcore.a $(SODIUM_LIBS) $(LIBINTL)

## The fault-injection shim is an LD_PRELOAD shared object, so it is built with
## an explicit rule rather than as a check_PROGRAM.  Listing it in check_DATA
## makes "make check" build it before the tests run; test_faults.sh skips
## itself cleanly on a platform where the preload is unavailable.
check_DATA = faultlib.so byteflip$(EXEEXT)
CLEANFILES = faultlib.so byteflip$(EXEEXT)
faultlib.so: $(srcdir)/faultlib.c
	$(AM_V_CC)$(CC) -shared -fPIC -D_GNU_SOURCE $(CPPFLAGS) $(CFLAGS) \
	  -o $@ $(srcdir)/faultlib.c $(LDFLAGS) -ldl

## Reuse the audit byteflip helper to drive the tamper-detection test, rather
## than re-implementing an in-place byte flip in portable shell.
byteflip$(EXEEXT): $(top_srcdir)/audit/byteflip.c
	$(AM_V_CC)$(CC) $(CPPFLAGS) $(CFLAGS) \
	  -o $@ $(top_srcdir)/audit/byteflip.c $(LDFLAGS)

## Point the shell integration tests at the freshly built binary and helpers.
AM_TESTS_ENVIRONMENT = \
	GISP='$(abs_top_builddir)/src/gisp'; export GISP; \
	FAULTLIB='$(abs_builddir)/faultlib.so'; export FAULTLIB; \
	BYTEFLIP='$(abs_builddir)/byteflip$(EXEEXT)'; export BYTEFLIP;

TESTS = test_runner test_cli.sh test_vectors.sh test_faults.sh

## Shipped but not run automatically everywhere: the pinned format vectors and
## the fault-injection source compiled into the preload shim above.
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
