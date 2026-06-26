/* proof/overflow_proof.c -- CBMC proof harness for gisp's size arithmetic.

   Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>
   Distributed under the GNU General Public License v3 or later; NO WARRANTY.

   This proves, for ALL 64-bit inputs (not just sampled ones), that:
     * u64_add_overflow / u64_mul_overflow report overflow exactly when the
       true mathematical result does not fit in uint64_t, and compute the
       correct wrapped result otherwise; and
     * the decrypt-side expected_size computation never accepts a payload
       length whose true container size differs from the checked value -- i.e.
       a crafted length can never wrap around the size check.

   Run with CBMC (no libsodium needed):
     cbmc -I ../include proof/overflow_proof.c src/common.c \
          --function prove_size --unwind 2 --bounds-check --conversion-check

   The 128-bit reference arithmetic is the oracle; CBMC checks the 64-bit code
   against it over the entire input space.  */

#include <stdint.h>
#include "gisp.h"

/* CBMC provides these; the stubs let the file also compile with a normal
   compiler for the randomized differential test in tests/.  */
#ifdef __CPROVER
#  define ASSUME(c) __CPROVER_assume (c)
#  define ASSERT(c) __CPROVER_assert ((c), #c)
uint64_t nondet_u64 (void);
#else
#  include <assert.h>
#  define ASSUME(c) do { if (!(c)) return; } while (0)
#  define ASSERT(c) assert (c)
extern uint64_t nondet_u64 (void);
#endif

void
prove_add (void)
{
  uint64_t a = nondet_u64 (), b = nondet_u64 (), r = 0;
  int of = u64_add_overflow (a, b, &r);
  __uint128_t truth = (__uint128_t) a + b;
  ASSERT (of == (truth > UINT64_MAX));
  if (!of)
    ASSERT (r == (uint64_t) truth);
}

void
prove_mul (void)
{
  uint64_t a = nondet_u64 (), b = nondet_u64 (), r = 0;
  int of = u64_mul_overflow (a, b, &r);
  __uint128_t truth = (__uint128_t) a * b;
  ASSERT (of == (truth > UINT64_MAX));
  if (!of)
    ASSERT (r == (uint64_t) truth);
}

/* Verify the real container_size_for_payload() used by decrypt_file against
   128-bit reference arithmetic, over the entire input space.  */
void
prove_size (void)
{
  uint64_t payload = nondet_u64 ();

  uint64_t expected = 0;
  int of = container_size_for_payload (payload, &expected);

  __uint128_t tchunks = (payload == 0) ? 1
                        : ((__uint128_t) payload + CHUNK_SIZE - 1) / CHUNK_SIZE;
  __uint128_t treal = tchunks * (__uint128_t) CRYPTO_ABYTES
                    + (__uint128_t) HEADER_TOTAL_SIZE + payload;

  /* Whenever the code reports no overflow, the computed size must equal the
     true size, so no wrap can sneak an oversized payload past the check.  */
  ASSERT (of == (treal > UINT64_MAX));
  if (!of)
    ASSERT ((__uint128_t) expected == treal);
}
