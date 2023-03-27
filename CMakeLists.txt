cmake_minimum_required(VERSION 3.24)
project(wallet_kit_lib)

set(CMAKE_CXX_STANDARD 20)

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


#add_dependencies(wallet_kit_lib botan)
