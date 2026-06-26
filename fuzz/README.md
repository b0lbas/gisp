# Fuzzing gisp

Three libFuzzer harnesses (build with clang). All run under
AddressSanitizer + UndefinedBehaviorSanitizer.

| Harness | Target | What it checks |
|---------|--------|----------------|
| `fuzz_decrypt.c`   | `decrypt_file` on arbitrary bytes | the container parser (the only untrusted-input boundary) |
| `fuzz_roundtrip.c` | `decrypt(encrypt(x)) == x` | encode/decode correctness across the chunking and streamed/fixed paths |
| `fuzz_password.c`  | `read_password_fd` | line/length handling of untrusted passphrase sources |

## Build

```sh
SAN="-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -g -O1 -Iinclude"
clang $SAN src/common.c src/crypto.c src/terminal.c fuzz/fuzz_decrypt.c   -o fuzz_decrypt   -lsodium
clang $SAN src/common.c src/crypto.c src/terminal.c fuzz/fuzz_roundtrip.c -o fuzz_roundtrip -lsodium
clang $SAN src/common.c src/terminal.c               fuzz/fuzz_password.c -o fuzz_password  -lsodium
```

## Run

```sh
# Seed the parser fuzzer with a valid container (matching passphrase, cheap KDF):
mkdir corpus
printf 'testpassword123' > pw
printf 'seed' | ./src/gisp -e - -o corpus/seed.gisp --opslimit 1 --memlimit 8192 --passphrase-file pw

./fuzz_decrypt   corpus -dict=fuzz/gisp.dict -close_fd_mask=2
./fuzz_roundtrip -close_fd_mask=2
./fuzz_password  -close_fd_mask=2
```

Notes:

* `fuzz_decrypt.c` lowers the memory ceiling (`gisp_set_limits`) so the fuzzer
  spends its budget on the parser instead of legitimate multi-gigabyte Argon2id
  allocations.
* `-close_fd_mask=2` silences the target's stderr while keeping libFuzzer's own
  reports.
* These harnesses suit ClusterFuzzLite/OSS-Fuzz with no changes.
