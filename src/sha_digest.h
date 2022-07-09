#ifndef _SHA_DIGEST_
#define _SHA_DIGEST_
#include<openssl/evp.h>
#include<stdint.h>

extern void digest_message(const uint8_t *message, size_t message_len, uint8_t *digest, uint32_t *digest_len);

#endif
  