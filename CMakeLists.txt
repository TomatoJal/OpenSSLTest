cmake_minimum_required(VERSION 3.22)
project(OpenSSLTest)

# include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories("${PROJECT_SOURCE_DIR}/ThirdParty/googletest/googletest/include")

add_executable(
  happy_case
  happy_case.cpp
)

target_link_libraries(
  happy_case
  ${PROJECT_SOURCE_DIR}/ThirdParty/googletest/build/lib/libgtestd.a
  ${PROJECT_SOURCE_DIR}/ThirdParty/googletest/build/lib/libgmockd.a
  ${PROJECT_SOURCE_DIR}/ThirdParty/googletest/build/lib/libgtest_maind.a
  ${PROJECT_SOURCE_DIR}/ThirdParty/googletest/build/lib/libgmock_maind.a
)