#include "OpenSSLTest.h"
#include "base64.h"

class Base64Test : public OpenSSLTest
{
protected:
  void SetUp();
  void TearDown();
};

void Base64Test::SetUp()
{}

void Base64Test::TearDown()
{}

TEST_F(Base64Test, case1)
{
  bio_official_encode();
} 