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
  printf("Encode\n");
  memcpy(Data, expect_Data, expect_DataLen);
  DataLen = expect_DataLen;
  printf("DataLen     : %d\n", DataLen);
  printf("Data(hex)   : ");
  print_hex(Data, DataLen);
  if(encode(Data, DataLen, B64Data, &B64Len))
  {
    printf("B64Len      : %d\n", B64Len);
    printf("B64Data(str): %s\n", B64Data);
    printf("B64Data(hex): ");
    print_hex(B64Data, B64Len);
  }
  EXPECT_EQ(B64Len, expect_B64Len);
  EXPECT_ARRAY_EQ(B64Data, expect_B64Data, expect_B64Len);
}

void Base64Test::decode(const uint8_t *expect_B64Data, uint32_t expect_B64Len, const uint8_t *expect_Data, uint32_t expect_DataLen, int (*decode)(uint8_t*, uint32_t, uint8_t*, uint32_t*))
{
  printf("Decode\n");
  memcpy(B64Data, expect_B64Data, sizeof(expect_B64Data));
  B64Len = sizeof(expect_B64Data);
  printf("B64Len      : %d\n", B64Len);
  printf("B64Data(str): %s\n", B64Data);
  printf("B64Data(hex): ");
  print_hex(B64Data, B64Len);

  if(decode(B64Data, B64Len, Data, &DataLen))
  {
    printf("DataLen     : %d\n", DataLen);
    printf("Data(hex)   : ");
    print_hex(Data, DataLen);
  }

  EXPECT_EQ(DataLen, expect_DataLen);
  EXPECT_ARRAY_EQ(Data, expect_Data, expect_DataLen);
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