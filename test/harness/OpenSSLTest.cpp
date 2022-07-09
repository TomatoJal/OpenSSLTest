#include "OpenSSLTest.h"

void OpenSSLTest::EXPECT_ARRAY_EQ(const uint8_t *src, const uint8_t *dest, uint32_t len)
{
  for(uint32_t i=0; i<len; i++)
  {
    EXPECT_EQ(src[i], dest[i]);
  }
}

void OpenSSLTest::print_hex(const uint8_t *src, uint32_t len, bool space)
{
  for(uint32_t i=0; i<len; i++)
  {
    if(space)
      printf("%02X ", src[i]);
    else
      printf("%02X", src[i]);
  }
  printf("\n");
}