#include "OpenSSLTest.h"
#include "base64.h"

class Base64Test : public OpenSSLTest
{
protected:
  void SetUp();
  void TearDown();

protected:
  void encode(const uint8_t *expect_Data, uint32_t expect_DataLen, const uint8_t *expect_B64Data, uint32_t expect_B64Len, int (*encode)(uint8_t*, uint32_t, uint8_t*, uint32_t*));
  void decode(const uint8_t *expect_B64Data, uint32_t expect_B64Len, const uint8_t *expect_Data, uint32_t expect_DataLen, int (*decode)(uint8_t*, uint32_t, uint8_t*, uint32_t*));

protected:
  uint8_t  Data[64*1024];
  uint32_t DataLen;
  uint8_t  B64Data[86*1024];
  uint32_t B64Len;
};

void Base64Test::encode(const uint8_t *expect_Data, uint32_t expect_DataLen, const uint8_t *expect_B64Data, uint32_t expect_B64Len, int (*encode)(uint8_t*, uint32_t, uint8_t*, uint32_t*))
{
  int ret = 0;
  printf("Encode\n");
  memcpy(Data, expect_Data, expect_DataLen);
  DataLen = expect_DataLen;
  printf("DataLen     : %d\n", DataLen);
  printf("Data(hex)   : ");
  print_hex(Data, DataLen);

  ret = encode(Data, DataLen, B64Data, &B64Len);
  if(ret > 0)
  {
    printf("B64Len      : %d\n", B64Len);
    printf("B64Data(str): %s\n", B64Data);
    printf("B64Data(hex): ");
    print_hex(B64Data, B64Len);
    EXPECT_EQ(B64Len, expect_B64Len);
    EXPECT_ARRAY_EQ(B64Data, expect_B64Data, expect_B64Len);
  }
  else
  {
    EXPECT_LE(ret, 0);
  }
}

void Base64Test::decode(const uint8_t *expect_B64Data, uint32_t expect_B64Len, const uint8_t *expect_Data, uint32_t expect_DataLen, int (*decode)(uint8_t*, uint32_t, uint8_t*, uint32_t*))
{
  int ret = 0;
  printf("Decode\n");
  memcpy(B64Data, expect_B64Data, expect_B64Len);
  B64Len = expect_B64Len;
  printf("B64Len      : %d\n", B64Len);
  printf("B64Data(str): %s\n", B64Data);
  printf("B64Data(hex): ");
  print_hex(B64Data, B64Len);

  ret = decode(B64Data, B64Len, Data, &DataLen);
  if(ret > 0)
  {
    printf("DataLen     : %d\n", DataLen);
    printf("Data(hex)   : ");
    print_hex(Data, DataLen);
    EXPECT_EQ(DataLen, expect_DataLen);
    EXPECT_ARRAY_EQ(Data, expect_Data, expect_DataLen);
  }
  else if(expect_Data == NULL || expect_DataLen == 0)
  {
    EXPECT_LE(ret, 0);
  }
  else
  {
    EXPECT_EQ(0, 1);
  }
}

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
  encode(expect_Data, sizeof(expect_Data), expect_B64Data, sizeof(expect_B64Data), bio_encode);

} 

TEST_F(Base64Test, BIO_Decode_A)
{
  const uint8_t expect_Data[]    = {0x41};
  const uint8_t expect_B64Data[] = {0x51,0x51,0x3d,0x3d};
  decode(expect_B64Data, sizeof(expect_B64Data), expect_Data, sizeof(expect_Data), bio_decode);
} 

TEST_F(Base64Test, EVP_block_Encode_A)
{
  const uint8_t expect_Data[]    = {0x41};
  const uint8_t expect_B64Data[] = {0x51,0x51,0x3d,0x3d};
  encode(expect_Data, sizeof(expect_Data), expect_B64Data, sizeof(expect_B64Data), EVP_block_encode);

} 

TEST_F(Base64Test, EVP_block_Decode_A)
{
  const uint8_t expect_Data[]    = {0x41};
  const uint8_t expect_B64Data[] = {0x51,0x51,0x3d,0x3d};
  decode(expect_B64Data, sizeof(expect_B64Data), expect_Data, sizeof(expect_Data), EVP_block_decode);
} 

TEST_F(Base64Test, EVP_Encode_A)
{
  const uint8_t expect_Data[]    = {0x41};
  const uint8_t expect_B64Data[] = {0x51,0x51,0x3d,0x3d};
  encode(expect_Data, sizeof(expect_Data), expect_B64Data, sizeof(expect_B64Data), EVP_encode);

} 

TEST_F(Base64Test, EVP_Decode_A)
{
  const uint8_t expect_Data[]    = {0x41};
  const uint8_t expect_B64Data[] = {0x51,0x51,0x3d,0x3d};
  decode(expect_B64Data, sizeof(expect_B64Data), expect_Data, sizeof(expect_Data), EVP_decode);
} 

TEST_F(Base64Test, BIO_Decode_QUJDRA)
{
  const uint8_t expect_Data[]    = {0x41, 0x42, 0x43, 0x44};
  const uint8_t expect_B64Data[] = {0x51, 0x55, 0x4A, 0x44, 0x52, 0x41};
  decode(expect_B64Data, sizeof(expect_B64Data), expect_Data, sizeof(expect_Data), bio_decode);
} 

TEST_F(Base64Test, EVP_block_Decode_QUJDRA)
{
  const uint8_t expect_B64Data[] = {0x51, 0x55, 0x4A, 0x44, 0x52, 0x41};
  decode(expect_B64Data, sizeof(expect_B64Data), NULL, 0, EVP_block_decode);
} 

TEST_F(Base64Test, EVP_Decode_QUJDRA)
{
  const uint8_t expect_B64Data[] = {0x51, 0x55, 0x4A, 0x44, 0x52, 0x41};
  decode(expect_B64Data, sizeof(expect_B64Data), NULL, 0, EVP_decode);
} 

TEST_F(Base64Test, BIO_Decode_QUJDRAand2EQ)
{
  const uint8_t expect_Data[]    = {0x41, 0x42, 0x43, 0x44};
  const uint8_t expect_B64Data[] = {0x51, 0x55, 0x4A, 0x44, 0x52, 0x41, 0x3d, 0x3d};
  decode(expect_B64Data, sizeof(expect_B64Data), expect_Data, sizeof(expect_Data), bio_decode);
} 

TEST_F(Base64Test, EVP_block_Decode_QUJDRAand2EQ)
{
  const uint8_t expect_Data[]    = {0x41, 0x42, 0x43, 0x44};
  const uint8_t expect_B64Data[] = {0x51, 0x55, 0x4A, 0x44, 0x52, 0x41, 0x3d, 0x3d};
  decode(expect_B64Data, sizeof(expect_B64Data), expect_Data, sizeof(expect_Data), EVP_block_decode);
} 

TEST_F(Base64Test, EVP_Decode_QUJDRAand2EQ)
{
  const uint8_t expect_Data[]    = {0x41, 0x42, 0x43, 0x44};
  const uint8_t expect_B64Data[] = {0x51, 0x55, 0x4A, 0x44, 0x52, 0x41, 0x3d, 0x3d};
  decode(expect_B64Data, sizeof(expect_B64Data), expect_Data, sizeof(expect_Data), EVP_decode);
} 

TEST_F(Base64Test, BIO_Decode_QUFBand2EQ)
{
  const uint8_t expect_Data[]    = {0x41, 0x41, 0x41};
  const uint8_t expect_B64Data[] = {0x51, 0x55, 0x46, 0x42, 0x3D, 0x3D};
  decode(expect_B64Data, sizeof(expect_B64Data), expect_Data, sizeof(expect_Data), bio_decode);
} 

TEST_F(Base64Test, EVP_block_Decode_QUFBand2EQ)
{
  const uint8_t expect_Data[]    = {0x41, 0x41, 0x41};
  const uint8_t expect_B64Data[] = {0x51, 0x55, 0x46, 0x42, 0x3D, 0x3D};
  decode(expect_B64Data, sizeof(expect_B64Data), NULL, 0, EVP_block_decode);
} 

TEST_F(Base64Test, EVP_Decode_QUFBand2EQ)
{
  const uint8_t expect_Data[]    = {0x41, 0x41, 0x41};
  const uint8_t expect_B64Data[] = {0x51, 0x55, 0x46, 0x42, 0x3D, 0x3D};
  decode(expect_B64Data, sizeof(expect_B64Data), NULL, 0, EVP_decode);
} 

TEST_F(Base64Test, BIO_Decode_QUFBand4EQ)
{
  const uint8_t expect_Data[]    = {0x41, 0x41, 0x41};
  const uint8_t expect_B64Data[] = {0x51, 0x55, 0x46, 0x42, 0x3D, 0x3D, 0x3D, 0x3D};
  decode(expect_B64Data, sizeof(expect_B64Data), expect_Data, sizeof(expect_Data), bio_decode);
} 

TEST_F(Base64Test, EVP_block_Decode_QUFBand4EQ)
{
  const uint8_t expect_Data[]    = {0x41, 0x41, 0x41};
  const uint8_t expect_B64Data[] = {0x51, 0x55, 0x46, 0x42, 0x3D, 0x3D, 0x3D, 0x3D};
  decode(expect_B64Data, sizeof(expect_B64Data), expect_Data, sizeof(expect_Data), EVP_block_decode);
} 

TEST_F(Base64Test, EVP_Decode_QUFBand4EQ)
{
  const uint8_t expect_Data[]    = {0x41, 0x41, 0x41};
  const uint8_t expect_B64Data[] = {0x51, 0x55, 0x46, 0x42, 0x3D, 0x3D, 0x3D, 0x3D};
  decode(expect_B64Data, sizeof(expect_B64Data), NULL, 0, EVP_decode);
} 

TEST_F(Base64Test, BIO_Decode_Band3EQ)
{
  const uint8_t expect_B64Data[] = {0x42,0x3d,0x3d,0x3d};
  decode(expect_B64Data, sizeof(expect_B64Data), NULL, 0, bio_decode);
} 

TEST_F(Base64Test, EVP_block_Decode_Band3EQ)
{
  const uint8_t expect_B64Data[] = {0x42,0x3d,0x3d,0x3d};
  decode(expect_B64Data, sizeof(expect_B64Data), NULL, 0, EVP_block_decode);
} 

TEST_F(Base64Test, EVP_Decode_Band3EQ)
{
  const uint8_t expect_B64Data[] = {0x42,0x3d,0x3d,0x3d};
  decode(expect_B64Data, sizeof(expect_B64Data), NULL, 0, EVP_decode);
} 

TEST_F(Base64Test, BIO_Decode_QQ)
{
  const uint8_t expect_B64Data[] = {0x51, 0x51};
  decode(expect_B64Data, sizeof(expect_B64Data), NULL, 0, bio_decode);
} 

TEST_F(Base64Test, EVP_block_Decode_QQ)
{
  const uint8_t expect_B64Data[] = {0x51, 0x51};
  decode(expect_B64Data, sizeof(expect_B64Data), NULL, 0, EVP_block_decode);
} 

TEST_F(Base64Test, EVP_Decode_QQ)
{
  const uint8_t expect_B64Data[] = {0x51, 0x51};
  decode(expect_B64Data, sizeof(expect_B64Data), NULL, 0, EVP_decode);
} 

TEST_F(Base64Test, BIO_Decode_QQand2EQ)
{
  const uint8_t expect_Data[]    = {0x41};
  const uint8_t expect_B64Data[] = {0x51, 0x51, 0x3D, 0x3D};
  decode(expect_B64Data, sizeof(expect_B64Data), expect_Data, sizeof(expect_Data), bio_decode);
} 

TEST_F(Base64Test, EVP_block_Decode_QQand2EQ)
{
  const uint8_t expect_Data[]    = {0x41};
  const uint8_t expect_B64Data[] = {0x51, 0x51, 0x3D, 0x3D};
  decode(expect_B64Data, sizeof(expect_B64Data), expect_Data, sizeof(expect_Data), EVP_block_decode);
} 

TEST_F(Base64Test, EVP_Decode_QQand2EQ)
{
  const uint8_t expect_Data[]    = {0x41};
  const uint8_t expect_B64Data[] = {0x51, 0x51, 0x3D, 0x3D};
  decode(expect_B64Data, sizeof(expect_B64Data), expect_Data, sizeof(expect_Data), EVP_decode);
} 

TEST_F(Base64Test, BIO_Decode_4EQ)
{
  const uint8_t expect_B64Data[] = {0x3d, 0x3d, 0x3d, 0x3d};
  decode(expect_B64Data, sizeof(expect_B64Data), NULL, 0, bio_decode);
} 

TEST_F(Base64Test, EVP_block_Decode_4EQ)
{
  const uint8_t expect_B64Data[] = {0x3d, 0x3d, 0x3d, 0x3d};
  decode(expect_B64Data, sizeof(expect_B64Data), NULL, 0, EVP_block_decode);
} 

TEST_F(Base64Test, EVP_Decode_4EQ)
{
  const uint8_t expect_B64Data[] = {0x3d, 0x3d, 0x3d, 0x3d};
  decode(expect_B64Data, sizeof(expect_B64Data), NULL, 0, EVP_decode);
} 



TEST_F(Base64Test, BIO_Decode_QQand2EQQQand2EQ)
{
  const uint8_t expect_B64Data[] = {0x51, 0x51, 0x3d, 0x3d, 0x51, 0x51, 0x3d, 0x3d};
  decode(expect_B64Data, sizeof(expect_B64Data), NULL, 0, bio_decode);
} 

TEST_F(Base64Test, EVP_block_Decode_QQand2EQQQand2EQ)
{
  const uint8_t expect_B64Data[] = {0x51, 0x51, 0x3d, 0x3d, 0x51, 0x51, 0x3d, 0x3d};
  decode(expect_B64Data, sizeof(expect_B64Data), NULL, 0, EVP_block_decode);
} 

TEST_F(Base64Test, EVP_Decode_QQand2EQQQand2EQ)
{
  const uint8_t expect_B64Data[] = {0x51, 0x51, 0x3d, 0x3d, 0x51, 0x51, 0x3d, 0x3d};
  decode(expect_B64Data, sizeof(expect_B64Data), NULL, 0, EVP_decode);
} 