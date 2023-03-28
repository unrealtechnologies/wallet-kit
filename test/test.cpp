//
// Created by Ariel Saldana on 3/27/23.
//

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <wallet-kit/bip39.h>
#include <utils.h>

uint32_t factorial( uint32_t number ) {
    return number <= 1 ? number : factorial(number-1) * number;
}

TEST_CASE( "Factorials are computed", "[factorial]" ) {
    REQUIRE( factorial( 1) == 1 );
    REQUIRE( factorial( 2) == 2 );
    REQUIRE( factorial( 3) == 6 );
    REQUIRE( factorial(10) == 3'628'800 );
}

TEST_CASE( "Bip39 mnemonics are derived correctly", "[entropyToMnemonic]" ) {
    std::string entropyHexStr = "c94c3a10b50450a4eaeee90e45ca90f551ef08266942b4bc4ad821e517e7a24a";
    std::vector<uint8_t> entropyBytes = walletKitUtils::hexStringToBytes(entropyHexStr);
    auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);
    REQUIRE( mnemonic == "sing gift loud head eagle fame produce tag atom comic picnic turkey bus lottery often choose regret time render duck fabric video matrix fortune" );
}

TEST_CASE( "Bip39 seed is derived correctly from mnemonic", "[entropyToMnemonic]" ) {
    std::string mnemonic = "sing gift loud head eagle fame produce tag atom comic picnic turkey bus lottery often choose regret time render duck fabric video matrix fortune";
    auto seed = Bip39::mnemonicToSeed(mnemonic);
    auto seedHex = walletKitUtils::to_hex(seed, 64);
    REQUIRE( seedHex == "8b3d3c2f07e8eefee19f3426607d4ed156aac2c3362a05746827c85954e60a10ae78b5a04c195ebbd53e2abb34c3d4989fd635c7dd1c151f6a7c16439a6c9dda");
}