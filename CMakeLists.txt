#cmake_minimum_required(VERSION 3.24)
#project(wallet_kit_lib)
#
#set(CMAKE_CXX_STANDARD 20)
#
#MESSAGE(${CMAKE_BINARY_DIR})
#
#set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
#set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
#
#message(STATUS "Fetching Catch2")
#include(FetchContent)
#FetchContent_Declare(
#        Catch2
#        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
#        GIT_TAG devel
#)
#FetchContent_MakeAvailable(Catch2)
#
#message(STATUS "Fetching botan")
#include(FetchContent)
#FetchContent_Declare(
#        botan
#        GIT_REPOSITORY https://github.com/randombit/botan.git
#        GIT_TAG 2.19.3
#)
#FetchContent_MakeAvailable(botan)
##
##
##if (NOT TARGET Catch2)
##    add_subdirectory(${CMAKE_SOURCE_DIR}/third-party/Catch2)
##endif ()
##include_directories(${CMAKE_SOURCE_DIR}/third-party/Catch2/src)
##include_directories(${CMAKE_SOURCE_DIR}/third-party/Catch2/src/internal)
#
##link_directories(${CMAKE_SOURCE_DIR}/third-party/botan/build/include)
##include_directories(${CMAKE_SOURCE_DIR}/third-party/botan/build/include)
##MESSAGE(${CMAKE_SOURCE_DIR}/third-party/botan/build/include)
#
#add_library(wallet_kit_lib SHARED src/library.cpp include/wallet-kit/bip32.h src/bip32/bip32.cpp include/wallet-kit/bip39.h src/bip39/bip39.cpp include/wallet-kit/bip39/english_wordlist.h include/utils.h include/wallet-kit/bip32/extended_key.h src/bip32/extended_key.cpp include/wallet-kit/bip32/hdw.h src/bip32/hdw.cpp)
#
#target_link_libraries(
#        wallet_kit_lib
#        PRIVATE botan
##        ${CMAKE_SOURCE_DIR}/third-party/botan/libbotan-3.a
#)
#
## Add system-level include directories with angle brackets
#target_include_directories(wallet_kit_lib PUBLIC
#        ${CMAKE_CURRENT_SOURCE_DIR}/include
#        SYSTEM INTERFACE /usr/include
#        )
#
#add_executable(tests test/test.cpp)
#target_link_libraries(
#        tests
#        PRIVATE Catch2::Catch2WithMain
#        PRIVATE botan
#        wallet_kit_lib
#)
#
#target_include_directories(tests PUBLIC
#        ${CMAKE_CURRENT_SOURCE_DIR}/include
#        )
##add_dependencies(wallet_kit_lib botan)rof

cmake_minimum_required(VERSION 3.24)
project(wallet_kit_lib)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Fetch and configure Catch2
include(FetchContent)
FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG devel
)
FetchContent_MakeAvailable(Catch2)

### New Botan Include
include(FetchContent)
FetchContent_Declare(
        botan
        GIT_REPOSITORY https://github.com/randombit/botan.git
        GIT_TAG 2.19.3
)

FetchContent_GetProperties(botan)
string(TOLOWER "botan" lcName)
if (NOT ${lcName}_POPULATED)
    # This downloads botan, but nothing beyond that
    # Ideally we would also use a CONGIFURE step to avoid the extra
    # ExternalProject, but that is explicitly not supported
    FetchContent_Populate(botan)

    include(ExternalProject)
    set(botan_args
            --minimized-build
            --enable-modules=hash,bcrypt,scrypt,hex,system_rng,sha2_64,sha3,argon2,rmd160
            --disable-shared
            --prefix=${CMAKE_CURRENT_BINARY_DIR}/botan
            )

    MESSAGE(${${lcName}_SOURCE_DIR})
    MESSAGE(${${lcName}_BINARY_DIR})
    MESSAGE(${CMAKE_CURRENT_BINARY_DIR})
    ExternalProject_Add(botan_project
            SOURCE_DIR ${${lcName}_SOURCE_DIR}
            BINARY_DIR ${${lcName}_BINARY_DIR}
            UPDATE_COMMAND "" # Don't need to update since using tagged release
            CONFIGURE_COMMAND python ${${lcName}_SOURCE_DIR}/configure.py ${botan_args}
            BUILD_COMMAND make
            BUILD_BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/botan/lib/libbotan-2.a
            )

    add_library(Botan::botan STATIC IMPORTED GLOBAL)
    add_dependencies(Botan::botan botan_project)

    # Workaround for INTERFACE_INCLUDE_DIRECTORIES. The problem is the include
    # directory needs to exist at cmake configuration time even though it won't
    # exist until the external project is checked out at build time.
    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/botan/include/botan-2)

    set_target_properties(Botan::botan PROPERTIES
            IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/botan/lib/libbotan-2.a
            INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR}/botan/include/botan-2
            )
endif ()


# Define library target
add_library(wallet_kit_lib SHARED
        src/library.cpp
        src/bip32/bip32.cpp
        src/bip39/bip39.cpp
        src/bip32/extended_key.cpp
        src/bip32/hdw.cpp
        )

target_include_directories(wallet_kit_lib PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        )

target_link_libraries(wallet_kit_lib
        Botan::botan
        )

# Define tests target
add_executable(tests
        test/test.cpp
        )

target_include_directories(tests PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        )

target_link_libraries(tests
        PRIVATE Catch2::Catch2WithMain
        wallet_kit_lib
        )
