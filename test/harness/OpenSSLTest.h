#ifndef _OPENSSL_TEST_
#define _OPENSSL_TEST_
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <stdint.h>

using ::testing::_;

class OpenSSLTest : public ::testing::Test
{
public:
  OpenSSLTest() = default;

  virtual void SetUp() {};
  virtual void TearDown() {};

  inline void EXPECT_ARRAY_EQ(const uint8_t *src, const uint8_t *dest, uint32_t len);
  inline void print_hex(const uint8_t *src, uint32_t len);
};

inline void OpenSSLTest::EXPECT_ARRAY_EQ(const uint8_t *src, const uint8_t *dest, uint32_t len)
{
  for(uint32_t i=0; i<len; i++)
  {
    EXPECT_EQ(src[i], dest[i]);
  }
}

inline void OpenSSLTest::print_hex(const uint8_t *src, uint32_t len)
{
  for(uint32_t i=0; i<len; i++)
  {
    printf("%02X ", src[i]);
  }
  printf("\n");
}
#endif