cmake_minimum_required(VERSION 3.24)
project(enc3 C)

set(CMAKE_C_STANDARD 23)

add_executable(enc3 main.c)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(enc3 ${OPENSSL_LIBRARIES})