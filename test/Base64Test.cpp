#include "OpenSSLTest.h"
#include "base64.h"

class Base64Test : public OpenSSLTest
{
protected:
  void SetUp();
  void TearDown();

protected:
  uint8_t  Data[64*1024];
  uint32_t DataLen;
  uint8_t  B64Data[86*1024];
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

TEST_F(Base64Test, BIO_Encode_A)
{
  const uint8_t expect_Data[]    = {0x41};
  const uint8_t expect_B64Data[] = {0x51,0x51,0x3d,0x3d};
  
  memcpy(Data, expect_Data, sizeof(expect_Data));
  DataLen = sizeof(expect_Data);
  
  bio_encode(Data, DataLen, B64Data, &B64Len);
  EXPECT_EQ(B64Len, sizeof(expect_B64Data));
  EXPECT_ARRAY_EQ(B64Data, expect_B64Data, sizeof(expect_B64Data));
} 

TEST_F(Base64Test, BIO_Dncode_A)
{
  const uint8_t expect_Data[]    = {0x41};
  const uint8_t expect_B64Data[] = {0x51,0x51,0x3d,0x3d};
  
  memcpy(B64Data, expect_B64Data, sizeof(expect_B64Data));
  B64Len = sizeof(expect_B64Data);
  
  bio_decode(B64Data, B64Len, Data, &DataLen);
  EXPECT_EQ(DataLen, sizeof(expect_Data));
  EXPECT_ARRAY_EQ(Data, expect_Data, sizeof(expect_Data));
} 