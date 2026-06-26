/* constants.c -- print the real container layout constants for
   spec-vs-code checking.

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
#include "gisp.h"
int main(void){
  printf("MAGIC offset/size      : %d / 4\n", OFST_MAGIC);
  printf("VERSION offset/size    : %d / 2\n", OFST_VERSION);
  printf("OPSLIMIT offset/size   : %d / 8\n", OFST_OPSLIMIT);
  printf("MEMLIMIT offset/size   : %d / 8\n", OFST_MEMLIMIT);
  printf("SALT offset/size       : %d / %d\n", OFST_SALT, (int)SALT_SIZE);
  printf("PAYLOAD_LEN offset/size: %d / 8\n", OFST_PAYLOAD);
  printf("METADATA_BASE_SIZE(AAD): %d\n", (int)METADATA_BASE_SIZE);
  printf("STREAM_HDR offset/size : %d / %d\n", (int)METADATA_BASE_SIZE, (int)STREAM_HDR_SIZE);
  printf("HEADER_TOTAL_SIZE      : %d  (chunks start here)\n", (int)HEADER_TOTAL_SIZE);
  printf("CRYPTO_ABYTES per chunk: %d\n", (int)CRYPTO_ABYTES);
  printf("CHUNK_SIZE             : %d\n", (int)CHUNK_SIZE);
  printf("PAYLOAD_LEN_UNKNOWN    : 0x%016llx\n", (unsigned long long)PAYLOAD_LEN_UNKNOWN);
  return 0;
}
