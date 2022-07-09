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
  int read_length;
  char inbuf[512];
  int inlen;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_mem_buf(B64Data, B64Len);

  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

  BIO_push(b64, bio);
  
  read_length = BIO_read(b64, Data, B64Len);
  if(read_length <= 0)
  {
    printf("Encode BIO_read error: return %d", read_length);
  }
  *DataLen = read_length;
  BIO_flush(b64);
  BIO_free_all(b64);
  return read_length;
}