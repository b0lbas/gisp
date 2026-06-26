# Releasing gisp

GNU practice is to ship a signed source tarball. These steps are run by the
maintainer; they need your OpenPGP key and cannot be automated in the repo.

## 1. Pre-release checks

```sh
./autogen.sh
./configure
make
make check                 # unit + CLI + known-answer vector tests
make distcheck             # builds the tarball, then builds+tests it clean
                           # (needs TeX for the PDF manual; Info builds without)
```

Also recommended before tagging:

```sh
# sanitizers
cc -fsanitize=address,undefined -Iinclude src/common.c src/crypto.c \
   src/terminal.c tests/test_core.c -o t-asan -lsodium && ./t-asan

# static analysis
for f in src/*.c; do gcc -fanalyzer -Iinclude -O2 -c "$f" -o /dev/null; done

# size-math differential check
gcc -O2 -Iinclude tests/overflow_diff.c proof/overflow_proof.c src/common.c \
    -o odiff -lsodium && ./odiff
```

## 2. Bump the version

Update `AC_INIT(...)` in `configure.ac` and the `NEWS` heading, then commit.

## 3. Build the distribution tarball

```sh
make dist                  # produces gisp-X.Y.tar.gz
```

## 4. Sign it (detached, ASCII-armored)

```sh
gpg --armor --detach-sign gisp-X.Y.tar.gz      # -> gisp-X.Y.tar.gz.asc
sha256sum gisp-X.Y.tar.gz > gisp-X.Y.tar.gz.sha256
```

Publish your public key (e.g. on keys.openpgp.org) and link its fingerprint
from the README so users can verify:

```sh
gpg --verify gisp-X.Y.tar.gz.asc gisp-X.Y.tar.gz
```

## 5. Upload

Upload the tarball, `.asc`, and `.sha256` to the release area (Savannah's
download area once approved). Tag the release in git:

```sh
git tag -s vX.Y -m "gisp X.Y"      # signed tag
git push --tags
```

## Notes for the GNU submission

* GNU requires release tarballs to be GPG-signed — the `.asc` above satisfies
  this.
* Once accepted, GNU provides `gnupload` (in the gnulib/coreutils tooling) to
  upload signed tarballs to ftp.gnu.org; the manual steps above mirror it.
