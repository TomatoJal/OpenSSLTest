#ifndef _BASE64_
#define _BASE64_
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include <stdint.h>
#include <cstring>

extern int bio_encode(uint8_t *Data, uint32_t DataLen, uint8_t *B64Data, uint32_t *B64Len);
extern int bio_decode(uint8_t *B64Data, uint32_t B64Len, uint8_t *Data, uint32_t *DataLen);
extern int EVP_block_encode(uint8_t *Data, uint32_t DataLen, uint8_t *B64Data, uint32_t *B64Len);
extern int EVP_block_decode(uint8_t *B64Data, uint32_t B64Len, uint8_t *Data, uint32_t *DataLen);
extern int EVP_encode(uint8_t *Data, uint32_t DataLen, uint8_t *B64Data, uint32_t *B64Len);
extern int EVP_decode(uint8_t *B64Data, uint32_t B64Len, uint8_t *Data, uint32_t *DataLen);
#endif
  