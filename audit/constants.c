/* Print the real container layout constants for spec-vs-code checking. */
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
