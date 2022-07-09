#include "OpenSSLTest.h"
#include "base64.h"

class Base64Test : public OpenSSLTest
{
protected:
  void SetUp();
  void TearDown();

protected:
  uint8_t Data[64*1024];
  uint32_t DataLen;
  uint8_t B64Data[86*1024];
  uint32_t B64Len;
};

void Base64Test::SetUp()
{
  memset(Data, sizeof(Data), 0);
  DataLen = 0;
  memset(B64Data, sizeof(B64Data), 0);
  B64Len = 0;
}

void Base64Test::TearDown()
{}

TEST_F(Base64Test, BIO_ENCODE_A)
{
  Data[0] = 'A';
  DataLen = 1;
  uint8_t expect_B64Data[] = {0x51,0x51,0x3d,0x3d,'\0'};
  bio_official_encode(Data, DataLen, B64Data, &B64Len);
  EXPECT_EQ(B64Len, 4);
  EXPECT_STREQ((char *)B64Data, (char *)expect_B64Data);
} 