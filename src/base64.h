#ifndef _BASE64_
#define _BASE64_
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <cstring>

extern int bio_official_encode(uint8_t * Data, uint32_t DataLen, uint8_t * B64Data, uint32_t * B64Len);
#endif
  