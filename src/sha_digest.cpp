#include "sha_digest.h"

// void digest_message(const uint8_t *message, size_t message_len, uint8_t *digest, uint32_t *digest_len)
// {
//   EVP_MD_CTX *mdctx;

//   if((mdctx = EVP_MD_CTX_new()) == NULL)
//     printf("EVP_MD_CTX_new Error");

//   if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
//     printf("EVP_DigestInit_ex Error");

//   if(1 != EVP_DigestUpdate(mdctx, message, message_len))
//     printf("EVP_DigestUpdate Error");

//   // if((*digest = (uint8_t *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
//   // 	printf("OPENSSL_malloc Error");

//   if(1 != EVP_DigestFinal_ex(mdctx, digest, digest_len))
//     printf("EVP_DigestFinal_ex Error");

//   for(uint32_t i=0; i<*digest_len ;i++)
//   {
//   printf("%02X", digest[i]);
//   }
//   printf("\n");
//   EVP_MD_CTX_free(mdctx);
// }

uint32_t digest_message(const uint8_t *Data, uint32_t DataLen, uint8_t *hash, const EVP_MD *type)
{
  EVP_MD_CTX *mdctx;
  uint32_t hash_len = 0;

  if((mdctx = EVP_MD_CTX_new()) == NULL)
    printf("EVP_MD_CTX_new Error");

  if(1 != EVP_DigestInit(mdctx, type))
    printf("EVP_DigestInit Error");
  while(DataLen > 0)
  {
    if(DataLen > SegSize)
    {
      if(1 != EVP_DigestUpdate(mdctx, Data, SegSize))
        printf("EVP_DigestUpdate Error"); 
      Data += SegSize;
      DataLen -= SegSize;
    }
    else
    {
      if(1 != EVP_DigestUpdate(mdctx, Data, DataLen))
        printf("EVP_DigestUpdate Error"); 
      Data += DataLen;
      DataLen = 0;
    }
  }

  if(1 != EVP_DigestFinal(mdctx, hash, &hash_len))
    printf("EVP_DigestFinal Error");

  EVP_MD_CTX_free(mdctx);
  return hash_len;
}

EVP_MD_CTX* allocate()
{
  return EVP_MD_CTX_new();
}

int init(EVP_MD_CTX *mdctx, const EVP_MD *type)
{
  if(1 != EVP_DigestInit(mdctx, type))
  {
    printf("EVP_DigestInit Error");
    return 0;
  }
  return 1;
}

int update(EVP_MD_CTX *mdctx, const uint8_t *Data, uint32_t DataLen)
{
  if(DataLen > SegSize)
  {
    DataLen = SegSize;
  }
  if(1 != EVP_DigestUpdate(mdctx, Data, DataLen))
  {
    printf("EVP_DigestUpdate Error"); 
    return 0;
  }
  return 1;
}

int final(EVP_MD_CTX *mdctx, uint8_t *hash, uint32_t *HashLen)
{
  if(1 != EVP_DigestFinal(mdctx, hash, HashLen))
  {
    printf("EVP_DigestFinal Error");
    return 0;
  }
  return 1;
}

int free(EVP_MD_CTX *mdctx)
{
  EVP_MD_CTX_free(mdctx);
  return 1;
}