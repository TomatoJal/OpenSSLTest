#include "base64.h"

int bio_encode(uint8_t *Data, uint32_t DataLen, uint8_t *B64Data, uint32_t *B64Len)
{
  BIO *bio, *b64;
  BUF_MEM *buffer_pointer;

  int ret = 0;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());

  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

  BIO_push(b64, bio);
  ret = BIO_write(b64, Data, DataLen);
  if(ret <= 0)
  {
    printf("Encode BIO_write error: return %d", ret);
  }
  BIO_flush(b64);

  BIO_get_mem_ptr(bio, &buffer_pointer);
  memcpy(B64Data, buffer_pointer->data, buffer_pointer->length);
  *B64Len = buffer_pointer->length;
  BIO_free_all(b64);
  return ret;
}

int bio_decode(uint8_t *B64Data, uint32_t B64Len, uint8_t *Data, uint32_t *DataLen)
{
  BIO *bio, *b64, *bio_out;
  int ret;
  char inbuf[512];
  int inlen;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_mem_buf(B64Data, B64Len);

  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

  BIO_push(b64, bio);
  
  ret = BIO_read(b64, Data, B64Len);
  if(ret <= 0)
  {
    printf("Encode BIO_read error: return %d", ret);
  }
  *DataLen = ret;
  BIO_flush(b64);
  BIO_free_all(b64);
  return ret;
}

int EVP_block_encode(uint8_t *Data, uint32_t DataLen, uint8_t *B64Data, uint32_t *B64Len)
{
  int ret = 0;
  ret = EVP_EncodeBlock(B64Data, Data, DataLen);
  *B64Len = ret;
  return ret;
}

int EVP_block_decode(uint8_t *B64Data, uint32_t B64Len, uint8_t *Data, uint32_t *DataLen)
{
  int ret = 0;
  ret = EVP_DecodeBlock(Data, B64Data, B64Len);
  *DataLen = ret;
  return ret;
}

struct evp_Encode_Ctx_st {
    /* number saved in a partial encode/decode */
    int num;
    /*
     * The length is either the output line length (in input bytes) or the
     * shortest input line length that is ok.  Once decoding begins, the
     * length is adjusted up each time a longer line is decoded
     */
    int length;
    /* data to encode */
    unsigned char enc_data[80];
    /* number read on current line */
    int line_num;
    unsigned int flags;
};

/* EVP_ENCODE_CTX flags */
/* Don't generate new lines when encoding */
#define EVP_ENCODE_CTX_NO_NEWLINES          1
/* Use the SRP base64 alphabet instead of the standard one */
#define EVP_ENCODE_CTX_USE_SRP_ALPHABET     2

int EVP_encode(uint8_t *Data, uint32_t DataLen, uint8_t *B64Data, uint32_t *B64Len)
{
  int ret = 0;
  int total = 0;
  int outl = 0;
  EVP_ENCODE_CTX ectx;
  
  EVP_EncodeInit(&ectx);
  // evp_encode_ctx_set_flags(&ectx, EVP_ENCODE_CTX_NO_NEWLINES);
  ectx.flags = EVP_ENCODE_CTX_NO_NEWLINES; // should set after init
  ret = EVP_EncodeUpdate(&ectx, B64Data, &outl, Data, DataLen);
  if(ret <= 0)
  {
    printf("EVP_EncodeUpdate err! Return %d\n", ret);
  }
  total += outl;
  EVP_EncodeFinal(&ectx, B64Data+total, &outl);
  total += outl;
  *B64Len = total;
  return ret;
}

int EVP_decode(uint8_t *B64Data, uint32_t B64Len, uint8_t *Data, uint32_t *DataLen)
{
  int ret = 0;
  int total = 0;
  int outl = 0; 
  EVP_ENCODE_CTX dctx;

  EVP_DecodeInit(&dctx);
  ret=EVP_DecodeUpdate(&dctx, Data, &outl, B64Data, B64Len);
  if(ret < 0)
  {
    printf("EVP_DecodeUpdate err! Return %d\n", ret);
  }
  total += outl;
  ret = EVP_DecodeFinal(&dctx, Data, &outl);
  if(ret <= 0)
  {
    printf("EVP_DecodeFinal err! Return %d\n", ret);
  }
  total += outl;
  *DataLen = total;
  return ret;
}