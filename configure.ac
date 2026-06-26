dnl configure.ac -- Autoconf input for gisp.
dnl
dnl Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>
dnl
dnl This program is free software: you can redistribute it and/or modify it
dnl under the terms of the GNU General Public License as published by the Free
dnl Software Foundation, either version 3 of the License, or (at your option)
dnl any later version.  There is NO WARRANTY, to the extent permitted by law.

AC_PREREQ([2.69])
AC_INIT([gisp], [1.1], [cmrtumilovic@gmail.com], [gisp],
        [https://codeberg.org/artich0ke/gisp])
AC_CONFIG_SRCDIR([src/crypto.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([1.16 foreign subdir-objects -Wall])

dnl Enable common GNU/POSIX extensions (defines _GNU_SOURCE for asprintf etc.).
AC_USE_SYSTEM_EXTENSIONS

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_RANLIB
AM_PROG_AR

dnl Internationalisation via the system gettext (we do not bundle libintl).
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.21])

dnl libsodium provides every cryptographic primitive we use.
PKG_CHECK_MODULES([SODIUM], [libsodium])

dnl Optional security hardening.  Each flag is probed for support so the build
dnl still works on toolchains that lack it.  Distributions may also inject
dnl their own hardening through CFLAGS/LDFLAGS; this just provides a sane
dnl default for a plain ./configure.
AC_ARG_ENABLE([hardening],
  [AS_HELP_STRING([--disable-hardening],
                  [do not add security hardening compiler/linker flags])],
  [enable_hardening=$enableval], [enable_hardening=yes])

HARDENING_CFLAGS=
HARDENING_LDFLAGS=
AS_IF([test "x$enable_hardening" = xyes], [
  gl_save_CFLAGS=$CFLAGS
  for flag in -fstack-protector-strong -fstack-clash-protection \
              -fcf-protection=full -D_FORTIFY_SOURCE=3; do
    AC_MSG_CHECKING([whether $CC accepts $flag])
    CFLAGS="$gl_save_CFLAGS -O2 $flag -Werror"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [])],
      [AC_MSG_RESULT([yes]); HARDENING_CFLAGS="$HARDENING_CFLAGS $flag"],
      [AC_MSG_RESULT([no])])
  done
  CFLAGS=$gl_save_CFLAGS

  gl_save_LDFLAGS=$LDFLAGS
  for lflag in "-Wl,-z,relro" "-Wl,-z,now" "-Wl,-z,noexecstack"; do
    AC_MSG_CHECKING([whether the linker accepts $lflag])
    LDFLAGS="$gl_save_LDFLAGS $lflag"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])],
      [AC_MSG_RESULT([yes]); HARDENING_LDFLAGS="$HARDENING_LDFLAGS $lflag"],
      [AC_MSG_RESULT([no])])
  done
  LDFLAGS=$gl_save_LDFLAGS
])
AC_SUBST([HARDENING_CFLAGS])
AC_SUBST([HARDENING_LDFLAGS])

AC_CONFIG_FILES([
  Makefile
  src/Makefile
  doc/Makefile
  tests/Makefile
  po/Makefile.in
])
AC_OUTPUT

echo "
  $PACKAGE_NAME $PACKAGE_VERSION

  prefix:      ${prefix}
  compiler:    ${CC} ${CFLAGS}
  NLS/gettext: ${USE_NLS}
"
