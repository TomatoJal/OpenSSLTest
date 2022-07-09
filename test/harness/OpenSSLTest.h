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
};

#endif