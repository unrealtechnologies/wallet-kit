cmake_minimum_required(VERSION 3.24)
project(wallet_kit_lib)

set(CMAKE_CXX_STANDARD 20)

message(STATUS "Fetching Catch2")
include(FetchContent)
FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG        devel
)
FetchContent_MakeAvailable(Catch2)
#
#
#if (NOT TARGET Catch2)
#    add_subdirectory(${CMAKE_SOURCE_DIR}/third-party/Catch2)
#endif ()
#include_directories(${CMAKE_SOURCE_DIR}/third-party/Catch2/src)
#include_directories(${CMAKE_SOURCE_DIR}/third-party/Catch2/src/internal)

link_directories(${CMAKE_SOURCE_DIR}/third-party/botan/build/include)
include_directories(${CMAKE_SOURCE_DIR}/third-party/botan/build/include)
MESSAGE(${CMAKE_SOURCE_DIR}/third-party/botan/build/include)

add_library(wallet_kit_lib SHARED src/library.cpp include/wallet-kit/bip32.h src/bip32/bip32.cpp include/wallet-kit/bip39.h src/bip39/bip39.cpp include/wallet-kit/bip39/english_wordlist.h include/utils.h)

target_link_libraries(
        wallet_kit_lib
#        PRIVATE botan
        ${CMAKE_SOURCE_DIR}/third-party/botan/libbotan-3.a
)

# Add system-level include directories with angle brackets
target_include_directories(wallet_kit_lib PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        SYSTEM INTERFACE /usr/include
        )

add_executable(tests test/test.cpp)
target_link_libraries(
        tests
        PRIVATE Catch2::Catch2WithMain
        wallet_kit_lib
)

target_include_directories(tests PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
#add_dependencies(wallet_kit_lib botan)rof
