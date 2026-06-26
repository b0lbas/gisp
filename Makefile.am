## Makefile.am -- top-level Automake input for gisp.
##
## Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>
## This file is distributed under the GNU General Public License v3 or later;
## there is NO WARRANTY, to the extent permitted by law.

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = po src doc tests

## The manual ships as Info/HTML, not PDF, so have "make distcheck" verify the
## documentation via "make info" (needs only texinfo's makeinfo) instead of the
## default "dvi" target, which would drag in a full TeX installation.
AM_DISTCHECK_DVI_TARGET = info

dist_man1_MANS = gisp.1

## Headers, security tooling and documents that live at the top level or in
## non-built subdirectories.
EXTRA_DIST = \
	include/gisp.h \
	include/gettext.h \
	README.md \
	SECURITY.md \
	.clang-format \
	ci/run.sh \
	audit/byteflip.c \
	proof/overflow_proof.c \
	fuzz/fuzz_decrypt.c \
	fuzz/fuzz_roundtrip.c \
	fuzz/fuzz_password.c \
	fuzz/gisp.dict \
	fuzz/README.md
