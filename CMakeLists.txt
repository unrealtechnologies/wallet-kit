cmake_minimum_required(VERSION 3.24)
set(CMAKE_CXX_STANDARD 20)

set(PROJECT_NAME "wallet_kit_lib")
project(${PROJECT_NAME} VERSION 1.0.0)

# Set up the build directory
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build/)
if (NOT EXISTS ${CMAKE_BINARY_DIR})
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR})
endif ()

MESSAGE(${CMAKE_BINARY_DIR})


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

# Fetch and configure secp256k1
include(FetchContent)
FetchContent_Declare(
        secp256k1
        GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1.git
        GIT_TAG master
)
FetchContent_MakeAvailable(secp256k1)

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
    set(CMAKE_PREFIX_PATH ${CMAKE_CURRENT_BINARY_DIR}/botan)
    #    find_package(Botan REQUIRED)
    # This downloads botan, but nothing beyond that
    # Ideally we would also use a CONGIFURE step to avoid the extra
    # ExternalProject, but that is explicitly not supported
    FetchContent_Populate(botan)

    include(ExternalProject)
    set(botan_args
            --minimized-build
            --enable-modules=hash,bcrypt,scrypt,hex,system_rng,sha2_64,sha3,argon2,rmd160,base58,keccak
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
        include/wallet-kit/bip32/chain_node.h src/bip32/chain_node.cpp src/utils.cpp include/wallet-kit/bip32/chain_node_context.h src/bip32/chain_node_context.cpp include/wallet-kit/cryptography/crypto_utils.h src/cryptography/crypto_utils.cpp include/wallet-kit/cryptography/cryptography_context.h src/cryptography/cryptography_context.cpp src/cryptography/crypto_utils.cpp include/wallet-kit/bip44/bip44.h include/wallet-kit/bip44/coin_type.h src/bip44/bip44.cpp)

target_compile_definitions(wallet_kit_lib
        PRIVATE LIBRARY_EXPORTS
        )

target_include_directories(wallet_kit_lib
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIVATE ${secp256k1_SOURCE_DIR}/include
        )

target_link_libraries(wallet_kit_lib
        Botan::botan
        secp256k1
        )

# Define tests target
add_executable(wallet_kit_tests
        test/test.cpp
        test/bip32_test_vector_4.cpp test/bip32_test_vector_2.cpp test/bip32_test_vector_3.cpp test/bip32_test_vector_1.cpp test/bip39_test_vector.cpp test/bip44_test_vector.cpp)

target_include_directories(wallet_kit_tests PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        )

target_link_libraries(wallet_kit_tests
        PRIVATE Catch2::Catch2WithMain
        PRIVATE wallet_kit_lib
        )
