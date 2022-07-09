#include "sha_digest.h"

void digest_message(const uint8_t *message, size_t message_len, uint8_t *digest, uint32_t *digest_len)
{
  EVP_MD_CTX *mdctx;

  if((mdctx = EVP_MD_CTX_new()) == NULL)
    printf("EVP_MD_CTX_new Error");

  if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
    printf("EVP_DigestInit_ex Error");

  if(1 != EVP_DigestUpdate(mdctx, message, message_len))
    printf("EVP_DigestUpdate Error");

  // if((*digest = (uint8_t *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
  // 	printf("OPENSSL_malloc Error");

  if(1 != EVP_DigestFinal_ex(mdctx, digest, digest_len))
    printf("EVP_DigestFinal_ex Error");

  for(uint32_t i=0; i<*digest_len ;i++)
  {
  printf("%02X", digest[i]);
  }
  printf("\n");
  EVP_MD_CTX_free(mdctx);
}