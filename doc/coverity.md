# Coverity Scan setup

Coverity Scan is free for open-source projects and is strong on C. A clean run
is good evidence for the GNU/OpenSSF review. These steps need a Coverity
account and project token, so they are run by the maintainer, not from the
repository.

## One-time

1. Register the project at <https://scan.coverity.com/> (sign in, "Add
   project", point it at the Codeberg/Savannah repository).
2. Download the **Coverity Build Tool** (`cov-analysis`) and note your
   **project token**.

## Each scan

```sh
./autogen.sh && ./configure
export PATH=/path/to/cov-analysis/bin:$PATH

# Build under Coverity's interception:
cov-build --dir cov-int make

# Package and upload:
tar czf gisp-cov.tgz cov-int
curl --form token=$COVERITY_TOKEN \
     --form email=cmrtumilovic@gmail.com \
     --form file=@gisp-cov.tgz \
     --form version="1.1" \
     --form description="gisp scan" \
     https://scan.coverity.com/builds?project=<your-project>
```

Review and triage findings in the Coverity web UI.

## Other analyzers worth a periodic run

These are not installed in the development sandbox but are easy to add:

```sh
cppcheck --enable=all --inconclusive -Iinclude src
semgrep --config p/c src
clang-tidy src/*.c -- -Iinclude -D_GNU_SOURCE
scan-build make                 # clang static analyzer over the whole build
```

For the formal size-math proof (when `cbmc` is installed):

```sh
cbmc -I include proof/overflow_proof.c src/common.c \
     --function prove_size --bounds-check --conversion-check --unwind 6
cbmc -I include proof/overflow_proof.c src/common.c --function prove_add
cbmc -I include proof/overflow_proof.c src/common.c --function prove_mul
```

---

Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>

Copying and distribution of this file, with or without modification, are
permitted in any medium without royalty provided the copyright notice and
this notice are preserved.  This file is offered as-is, without any warranty.
