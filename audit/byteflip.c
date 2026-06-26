/* byteflip.c -- flip (XOR 0xFF) one byte at a given offset, in place.
   Helper for the adversarial audit.  Usage: byteflip FILE OFFSET  */
#include <stdio.h>
#include <stdlib.h>

int
main (int argc, char **argv)
{
  if (argc < 3)
    return 2;
  FILE *f = fopen (argv[1], "r+b");
  if (!f)
    return 1;
  long off = atol (argv[2]);
  if (fseek (f, off, SEEK_SET) != 0)
    return 1;
  int c = fgetc (f);
  if (c == EOF)
    return 1;
  fseek (f, off, SEEK_SET);
  fputc (c ^ 0xFF, f);
  fclose (f);
  return 0;
}
