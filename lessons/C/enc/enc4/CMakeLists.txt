cmake_minimum_required(VERSION 3.24)
project(enc4 C)

set(CMAKE_C_STANDARD 23)

add_executable(enc4 main.c)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(enc4 ${OPENSSL_LIBRARIES})