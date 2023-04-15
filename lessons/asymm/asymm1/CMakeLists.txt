cmake_minimum_required(VERSION 3.24)
project(asymm1 C)

set(CMAKE_C_STANDARD 23)

add_executable(asymm1 main.c)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(asymm1 ${OPENSSL_LIBRARIES})