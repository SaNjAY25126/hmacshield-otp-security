cmake_minimum_required(VERSION 3.16)
project(secure_otp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_executable(secure_otp src/main.cpp)
target_link_libraries(secure_otp PRIVATE OpenSSL::Crypto)

if(MSVC)
  target_compile_options(secure_otp PRIVATE /W4 /permissive-)
else()
  target_compile_options(secure_otp PRIVATE -Wall -Wextra -Wpedantic)
endif()
