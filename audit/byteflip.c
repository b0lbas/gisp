/* byteflip.c -- flip (XOR 0xFF) one byte at a given offset, in place.
   Helper for the adversarial audit.  Usage: byteflip FILE OFFSET

   Copyright (C) 2026 Uladzislau Bolbas <cmrtumilovic@gmail.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */
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
  int c;
  int rc = 1;

  /* Every error path funnels through the single close below, so the stream is
     never leaked, and a write error that only surfaces at fclose is reported.  */
  if (fseek (f, off, SEEK_SET) != 0)
    goto done;
  c = fgetc (f);
  if (c == EOF)
    goto done;
  if (fseek (f, off, SEEK_SET) != 0)
    goto done;
  if (fputc (c ^ 0xFF, f) == EOF)
    goto done;
  rc = 0;

done:
  if (fclose (f) != 0)
    rc = 1;
  return rc;
}
