#include "OpenSSLTest.h"
#include "sha_digest.h"

class SHA2Test : public OpenSSLTest
{
public:
  void SetUp() final;
  void TearDown() final;

protected:
  uint8_t Data[8*1024];
  uint32_t DataLen;
  uint8_t Hash[64 + 1];
  uint32_t HashLen;
};

void SHA2Test::SetUp()
{
  memset(Data, sizeof(Data), 0);
  memset(Hash, sizeof(Hash), 0);
  DataLen = 0;
  HashLen = 0;
}

void SHA2Test::TearDown()
{}

TEST_F(SHA2Test, Hash2256_A)
{
  Data[0] = 'A';
  DataLen = 1;
  uint8_t ExpectHash[] = {
      0x55,0x9a,0xea,0xd0,0x82,0x64,0xd5,0x79,
      0x5d,0x39,0x09,0x71,0x8c,0xdd,0x05,0xab,
      0xd4,0x95,0x72,0xe8,0x4f,0xe5,0x55,0x90,
      0xee,0xf3,0x1a,0x88,0xa0,0x8f,0xdf,0xfd,
      0x00};
  digest_message(Data, DataLen, Hash, &HashLen);

  EXPECT_EQ(HashLen, 32);
}