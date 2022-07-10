#ifndef _SHA_DIGEST_
#define _SHA_DIGEST_
#include<openssl/evp.h>
#include<stdint.h>

#define SegSize (8*1024)

// extern void digest_message(const uint8_t *message, size_t message_len, uint8_t *digest, uint32_t *digest_len);
extern uint32_t digest_message(const uint8_t *Data, uint32_t DataLen, uint8_t *hash, const EVP_MD *type);

extern EVP_MD_CTX* allocate();
extern int init(EVP_MD_CTX *mdctx, const EVP_MD *type);
extern int update(EVP_MD_CTX *mdctx, const uint8_t *Data, uint32_t DataLen);
extern int final(EVP_MD_CTX *mdctx, uint8_t *hash, uint32_t *HashLen);
extern int free(EVP_MD_CTX *mdctx);

#endif
  