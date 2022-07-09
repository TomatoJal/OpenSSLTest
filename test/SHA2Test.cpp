#include "OpenSSLTest.h"
#include "sha_digest.h"

class SHA2Test : public OpenSSLTest
{
public:
  void SetUp() final;
  void TearDown() final;

protected:
  uint8_t  Data[8*8*1024];
  uint32_t DataLen;
  uint8_t  Hash[512/8];
  uint32_t HashLen;
};

void SHA2Test::SetUp()
{
  memset(Data, sizeof(Data), 0);
  memset(Hash, sizeof(Hash), 0);
  DataLen = 0;
}

void SHA2Test::TearDown()
{}

TEST_F(SHA2Test, abc)
{
  uint8_t test_data[] = {0x61, 0x62, 0x63};
  uint8_t sha224[] = {0x23,0x09,0x7d,0x22,0x34,0x05,0xd8,0x22,0x86,0x42,0xa4,0x77,0xbd,0xa2,0x55,0xb3,0x2a,0xad,0xbc,0xe4,0xbd,0xa0,0xb3,0xf7,0xe3,0x6c,0x9d,0xa7};
  uint8_t sha256[] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
  uint8_t sha384[] = {0xcb,0x00,0x75,0x3f,0x45,0xa3,0x5e,0x8b,0xb5,0xa0,0x3d,0x69,0x9a,0xc6,0x50,0x07,0x27,0x2c,0x32,0xab,0x0e,0xde,0xd1,0x63,0x1a,0x8b,0x60,0x5a,0x43,0xff,0x5b,0xed,0x80,0x86,0x07,0x2b,0xa1,0xe7,0xcc,0x23,0x58,0xba,0xec,0xa1,0x34,0xc8,0x25,0xa7};
  uint8_t sha512[] = {0xdd,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba,0xcc,0x41,0x73,0x49,0xae,0x20,0x41,0x31,0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2,0x0a,0x9e,0xee,0xe6,0x4b,0x55,0xd3,0x9a,0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8,0x36,0xba,0x3c,0x23,0xa3,0xfe,0xeb,0xbd,0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e,0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f};

  DataLen = sizeof(test_data);
  memcpy(Data, test_data, DataLen);

  printf("Data   : ");
  print_hex(Data, DataLen, false);
  HashLen = digest_message(Data, DataLen, Hash, EVP_sha224());
  EXPECT_EQ(HashLen, 224/8);
  EXPECT_ARRAY_EQ(Hash, sha224, HashLen);
  printf("Hash224: ");
  print_hex(Hash, HashLen, false);

  HashLen = digest_message(Data, DataLen, Hash, EVP_sha256());
  EXPECT_EQ(HashLen, 256/8);
  EXPECT_ARRAY_EQ(Hash, sha256, HashLen);
  printf("Hash256: ");
  print_hex(Hash, HashLen, false);

  HashLen = digest_message(Data, DataLen, Hash, EVP_sha384());
  EXPECT_EQ(HashLen, 384/8);
  EXPECT_ARRAY_EQ(Hash, sha384, HashLen);
  printf("Hash384: ");
  print_hex(Hash, HashLen, false);  

  HashLen = digest_message(Data, DataLen, Hash, EVP_sha512());
  EXPECT_EQ(HashLen, 512/8);
  EXPECT_ARRAY_EQ(Hash, sha512, HashLen);
  printf("Hash512: ");
  print_hex(Hash, HashLen, false);
}


TEST_F(SHA2Test, NULL)
{
  uint8_t sha224[] = {0xd1,0x4a,0x02,0x8c,0x2a,0x3a,0x2b,0xc9,0x47,0x61,0x02,0xbb,0x28,0x82,0x34,0xc4,0x15,0xa2,0xb0,0x1f,0x82,0x8e,0xa6,0x2a,0xc5,0xb3,0xe4,0x2f};
  uint8_t sha256[] = {0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55};
  uint8_t sha384[] = {0x38,0xb0,0x60,0xa7,0x51,0xac,0x96,0x38,0x4c,0xd9,0x32,0x7e,0xb1,0xb1,0xe3,0x6a,0x21,0xfd,0xb7,0x11,0x14,0xbe,0x07,0x43,0x4c,0x0c,0xc7,0xbf,0x63,0xf6,0xe1,0xda,0x27,0x4e,0xde,0xbf,0xe7,0x6f,0x65,0xfb,0xd5,0x1a,0xd2,0xf1,0x48,0x98,0xb9,0x5b};
  uint8_t sha512[] = {0xcf,0x83,0xe1,0x35,0x7e,0xef,0xb8,0xbd,0xf1,0x54,0x28,0x50,0xd6,0x6d,0x80,0x07,0xd6,0x20,0xe4,0x05,0x0b,0x57,0x15,0xdc,0x83,0xf4,0xa9,0x21,0xd3,0x6c,0xe9,0xce,0x47,0xd0,0xd1,0x3c,0x5d,0x85,0xf2,0xb0,0xff,0x83,0x18,0xd2,0x87,0x7e,0xec,0x2f,0x63,0xb9,0x31,0xbd,0x47,0x41,0x7a,0x81,0xa5,0x38,0x32,0x7a,0xf9,0x27,0xda,0x3e};

  DataLen = 0;
  printf("Data   : ");
  print_hex(Data, DataLen, false);
  HashLen = digest_message(NULL, DataLen, Hash, EVP_sha224());
  EXPECT_EQ(HashLen, 224/8);
  EXPECT_ARRAY_EQ(Hash, sha224, HashLen);
  printf("Hash224: ");
  print_hex(Hash, HashLen, false);

  HashLen = digest_message(NULL, DataLen, Hash, EVP_sha256());
  EXPECT_EQ(HashLen, 256/8);
  EXPECT_ARRAY_EQ(Hash, sha256, HashLen);
  printf("Hash256: ");
  print_hex(Hash, HashLen, false);

  HashLen = digest_message(NULL, DataLen, Hash, EVP_sha384());
  EXPECT_EQ(HashLen, 384/8);
  EXPECT_ARRAY_EQ(Hash, sha384, HashLen);
  printf("Hash384: ");
  print_hex(Hash, HashLen, false);  

  HashLen = digest_message(NULL, DataLen, Hash, EVP_sha512());
  EXPECT_EQ(HashLen, 512/8);
  EXPECT_ARRAY_EQ(Hash, sha512, HashLen);
  printf("Hash512: ");
  print_hex(Hash, HashLen, false);
}

TEST_F(SHA2Test, 32ka)
{
  uint8_t sha224[] = {0x3c,0x43,0x49,0x51,0xc3,0x2a,0xe1,0x0b,0x1f,0x2d,0xa9,0x5f,0xb8,0x94,0xc2,0x54,0x49,0x53,0x69,0x53,0x69,0xe8,0xee,0x43,0xd2,0x49,0x7c,0xef};
  uint8_t sha256[] = {0xb2,0x17,0xb6,0x5e,0x6f,0x20,0x5f,0x41,0xb3,0xfb,0x8e,0xf9,0x0c,0xf7,0xc4,0x4d,0xa9,0x3f,0x63,0x0c,0xa0,0x39,0x65,0x27,0x34,0x85,0xbb,0xb2,0x1a,0x5c,0xcc,0xf5};
  uint8_t sha384[] = {0x47,0x86,0x6c,0xa4,0xe9,0xc4,0x56,0x13,0xc8,0x9d,0xe8,0x92,0x56,0xb4,0x5f,0x68,0x24,0x5b,0xcd,0x06,0xbb,0x5a,0x58,0xbe,0x7f,0xf9,0x9f,0x7b,0x61,0xbd,0xcf,0x39,0x84,0x6e,0xa0,0x10,0x52,0x7b,0xfe,0xa4,0x24,0xaa,0x40,0xa6,0xa3,0xf4,0xbe,0xee};
  uint8_t sha512[] = {0x9b,0xd0,0xf5,0xf4,0xe6,0x00,0xca,0xcf,0xa4,0xef,0x0d,0x1d,0x4f,0x81,0x58,0x0d,0xc3,0x49,0xcb,0x5b,0x1a,0xd2,0xcd,0x7b,0x36,0x62,0xc3,0xbd,0x9e,0x2e,0xde,0x85,0x92,0xaf,0xc7,0xda,0xe9,0x86,0xd5,0x68,0x47,0xa0,0xb9,0x4e,0xb0,0xc9,0x6a,0x99,0x52,0xff,0x9c,0x2f,0x68,0x94,0x5c,0x09,0x96,0x83,0x70,0xfd,0x87,0x02,0x73,0xc4};

  DataLen = 32*1024;
  memset(Data, 0x61, DataLen);
  printf("Data   : 32ka\n");

  HashLen = digest_message(Data, DataLen, Hash, EVP_sha224());
  EXPECT_EQ(HashLen, 224/8);
  EXPECT_ARRAY_EQ(Hash, sha224, HashLen);
  printf("Hash224: ");
  print_hex(Hash, HashLen, false);

  HashLen = digest_message(Data, DataLen, Hash, EVP_sha256());
  EXPECT_EQ(HashLen, 256/8);
  EXPECT_ARRAY_EQ(Hash, sha256, HashLen);
  printf("Hash256: ");
  print_hex(Hash, HashLen, false);

  HashLen = digest_message(Data, DataLen, Hash, EVP_sha384());
  EXPECT_EQ(HashLen, 384/8);
  EXPECT_ARRAY_EQ(Hash, sha384, HashLen);
  printf("Hash384: ");
  print_hex(Hash, HashLen, false);  

  HashLen = digest_message(Data, DataLen, Hash, EVP_sha512());
  EXPECT_EQ(HashLen, 512/8);
  EXPECT_ARRAY_EQ(Hash, sha512, HashLen);
  printf("Hash512: ");
  print_hex(Hash, HashLen, false);
}