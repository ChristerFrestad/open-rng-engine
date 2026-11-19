/*
 * open-rng-engine evidence harness: TestU01 1.2.3 driver (tu01-driver v1).
 *
 * Decision rule v1 (FROZEN, sha256 5d09c75a...), rule 5: TestU01 1.2.3 on raw and on [0,2^32):
 * BigCrush (160 statistics) per RC, SmallCrush (15) nightly, Crush (144) weekly.
 * Rule 15 (TODO-CTO-2): "bbattery_BigCrush / SmallCrush / Crush through a pinned C driver over
 * unif01_CreateExternGenBits, on raw and on [0,2^32). The driver source is frozen with the harness."
 * The sha256 of this file is pinned in verification/harness/pins.mjs and checked by check:ph0.
 *
 * Input: 32-bit words on stdin, little-endian byte order, produced by the harness (raw stream or
 * the [0,2^32) mapped stream). The driver never wraps, reuses or pads input: running out of input
 * ends the process with exit 3; a trailing partial word ends it with exit 4.
 * Output (argv[3]): one header line, then one line per statistic in bbattery order:
 *   battery <TAB> stream <TAB> index <TAB> test-name <TAB> p-value (%.17g)
 * Rule 17(i) count check (verification/harness/counts.mjs) reads this file.
 * Usage: tu01-driver <SmallCrush|Crush|BigCrush> <raw|u32> <out.tsv>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "unif01.h"
#include "bbattery.h"

#define BUF_BYTES (1u << 20)

static unsigned char buf[BUF_BYTES];
static size_t have = 0;
static size_t pos = 0;
static unsigned long long words = 0;

static unsigned int next_word (void)
{
   uint32_t w;
   if (pos == have) {
      have = fread (buf, 1, BUF_BYTES, stdin);
      pos = 0;
      if (have == 0) {
         fprintf (stderr, "tu01-driver: input exhausted after %llu words\n", words);
         exit (3);
      }
      if (have % 4 != 0) {
         fprintf (stderr, "tu01-driver: trailing partial word after %llu words\n", words);
         exit (4);
      }
   }
   w = (uint32_t) buf[pos] | ((uint32_t) buf[pos + 1] << 8) |
       ((uint32_t) buf[pos + 2] << 16) | ((uint32_t) buf[pos + 3] << 24);
   pos += 4;
   words++;
   return (unsigned int) w;
}

int main (int argc, char *argv[])
{
   unif01_Gen *gen;
   FILE *out;
   int j;
   if (argc != 4 || (strcmp (argv[2], "raw") != 0 && strcmp (argv[2], "u32") != 0)) {
      fprintf (stderr, "usage: tu01-driver <SmallCrush|Crush|BigCrush> <raw|u32> <out.tsv>\n");
      return 2;
   }
   gen = unif01_CreateExternGenBits (argv[2], next_word);
   if (strcmp (argv[1], "BigCrush") == 0)
      bbattery_BigCrush (gen);
   else if (strcmp (argv[1], "SmallCrush") == 0)
      bbattery_SmallCrush (gen);
   else if (strcmp (argv[1], "Crush") == 0)
      bbattery_Crush (gen);
   else {
      fprintf (stderr, "tu01-driver: unknown battery %s\n", argv[1]);
      unif01_DeleteExternGenBits (gen);
      return 2;
   }
   unif01_DeleteExternGenBits (gen);
   out = fopen (argv[3], "w");
   if (out == NULL) {
      fprintf (stderr, "tu01-driver: cannot open %s\n", argv[3]);
      return 5;
   }
   fprintf (out, "# tu01-driver v1\tbattery=%s\tstream=%s\tntests=%d\twords=%llu\n",
      argv[1], argv[2], bbattery_NTests, words);
   for (j = 0; j < bbattery_NTests; j++)
      fprintf (out, "%s\t%s\t%d\t%s\t%.17g\n", argv[1], argv[2], j,
         bbattery_TestNames[j] ? bbattery_TestNames[j] : "-", bbattery_pVal[j]);
   if (fclose (out) != 0)
      return 5;
   return 0;
}
