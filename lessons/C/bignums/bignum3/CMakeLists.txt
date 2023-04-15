cmake_minimum_required(VERSION 3.24)
project(bignum3 C)

set(CMAKE_C_STANDARD 23)

add_executable(bignum3 main.c)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(bignum3 ${OPENSSL_LIBRARIES})