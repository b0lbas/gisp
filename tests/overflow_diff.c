/* tests/overflow_diff.c -- randomized differential driver for the size math.

   Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>
   Distributed under the GNU General Public License v3 or later; NO WARRANTY.

   Feeds edge-biased 64-bit values into the prove_* checks in
   proof/overflow_proof.c, which assert the 64-bit overflow code matches
   128-bit reference arithmetic.  A non-sampling proof needs CBMC; this gives
   strong empirical coverage with an ordinary compiler.  */

#include <stdint.h>
#include <stdio.h>

void prove_add (void);
void prove_mul (void);
void prove_size (void);

static uint64_t state = 0x123456789abcdef0ULL;

static uint64_t
xs (void)
{
  uint64_t x = state;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  return state = x;
}

/* Edge-biased generator so both the overflow and non-overflow branches, and
   the chunk/size boundaries, are exercised, not just random midrange values.  */
uint64_t
nondet_u64 (void)
{
  uint64_t r = xs ();
  switch (r & 7)
    {
    case 0:  return 0;
    case 1:  return UINT64_MAX;
    case 2:  return UINT64_MAX - (xs () & 0xffff);
    case 3:  return (uint64_t) 1 << (xs () % 64);
    case 4:  return (xs () % 9) * 65536 + (xs () % 3) - 1;   /* chunk edges */
    case 5:  return 0xffffffffULL + (int64_t) (xs () % 257) - 128; /* ~2^32 */
    default: return xs ();
    }
}

int
main (void)
{
  long n = 20000000;
  for (long i = 0; i < n; i++)
    {
      prove_add ();
      prove_mul ();
      prove_size ();
    }
  printf ("overflow differential: %ld iterations x3 checks, all assertions held\n",
          n);
  return 0;
}
