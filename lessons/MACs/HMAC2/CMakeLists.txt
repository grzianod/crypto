cmake_minimum_required(VERSION 3.24)
project(hmac2 C)

set(CMAKE_C_STANDARD 23)

add_executable(hmac2 main.c)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(hmac2 ${OPENSSL_LIBRARIES})