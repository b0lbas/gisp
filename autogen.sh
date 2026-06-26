#!/bin/sh
# autogen.sh -- regenerate the build system from a fresh checkout.
#
# Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>
# Distributed under the GNU General Public License v3 or later; NO WARRANTY.
#
# Run this once after cloning, then build the usual way:
#
#     ./autogen.sh && ./configure && make && make check
#
# Released tarballs already contain the generated files, so users building
# from a tarball do not need this script.

set -e
autoreconf --install --verbose
echo "Now run ./configure && make"
