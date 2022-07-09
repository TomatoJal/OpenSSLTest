cmake_minimum_required(VERSION 3.22)
project(OpenSSLTest)

aux_source_directory(src OpenSSLSrc)
aux_source_directory(test TestCases)
aux_source_directory(test/harness Harness)

include_directories(test/harness)
include_directories(src)
include_directories(ThirdParty/googletest/googletest/include)
include_directories(ThirdParty/googletest/googlemock/include)
include_directories(ThirdParty/openssl/include)
include_directories(ThirdParty/openssl/crypto/evp)

add_executable(
  OpenSSLGtest
  ${Harness}
  ${TestCases}
  ${OpenSSLSrc}
)

target_link_libraries(
  OpenSSLGtest
  ${PROJECT_SOURCE_DIR}/ThirdParty/openssl/libcrypto.a
  ${PROJECT_SOURCE_DIR}/ThirdParty/openssl/libssl.a
  libws2_32.a
  ${PROJECT_SOURCE_DIR}/ThirdParty/googletest/build/lib/libgtestd.a
  ${PROJECT_SOURCE_DIR}/ThirdParty/googletest/build/lib/libgmockd.a
  ${PROJECT_SOURCE_DIR}/ThirdParty/googletest/build/lib/libgtest_maind.a
  ${PROJECT_SOURCE_DIR}/ThirdParty/googletest/build/lib/libgmock_maind.a
)