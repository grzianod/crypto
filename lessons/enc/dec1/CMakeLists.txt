cmake_minimum_required(VERSION 3.24)
project(dec1 C)

set(CMAKE_C_STANDARD 23)

add_executable(dec1 main.c)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(dec1 ${OPENSSL_LIBRARIES})