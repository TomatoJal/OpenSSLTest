#ifndef _SHA_DIGEST_
#define _SHA_DIGEST_
#include<openssl/evp.h>
#include<stdint.h>

// extern void digest_message(const uint8_t *message, size_t message_len, uint8_t *digest, uint32_t *digest_len);
extern uint32_t digest_message(const uint8_t *Data, uint32_t DataLen, uint8_t *hash, const EVP_MD *type);
#endif
  