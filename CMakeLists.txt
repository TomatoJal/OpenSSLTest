cmake_minimum_required(VERSION 3.22)
project(OpenSSLTest)

aux_source_directory(src OpenSSLSrc)

include_directories(ThirdParty/googletest/googletest/include)
include_directories(ThirdParty/openssl/include)

add_executable(
  OpenSSLTest
  happy_case.cpp
  ${OpenSSLSrc}
)

target_link_libraries(
  OpenSSLTest
  ${PROJECT_SOURCE_DIR}/ThirdParty/openssl/libcrypto.a
  ${PROJECT_SOURCE_DIR}/ThirdParty/openssl/libssl.a
  libws2_32.a
  ${PROJECT_SOURCE_DIR}/ThirdParty/googletest/build/lib/libgtestd.a
  ${PROJECT_SOURCE_DIR}/ThirdParty/googletest/build/lib/libgmockd.a
  ${PROJECT_SOURCE_DIR}/ThirdParty/googletest/build/lib/libgtest_maind.a
  ${PROJECT_SOURCE_DIR}/ThirdParty/googletest/build/lib/libgmock_maind.a
)