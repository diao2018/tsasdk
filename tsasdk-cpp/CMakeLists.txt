cmake_minimum_required(VERSION 3.14)
project(tsasdk VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL 1.1.1 REQUIRED)
find_package(CURL REQUIRED)

add_library(tsasdk STATIC
    src/digest.cpp
    src/hash_util.cpp
    src/tsa_client.cpp
)

target_include_directories(tsasdk PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(tsasdk PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
)

# Demo executable
add_executable(tsasdk_demo src/demo.cpp)
target_link_libraries(tsasdk_demo PRIVATE tsasdk)
