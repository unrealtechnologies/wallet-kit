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
    std::string mnemonicRealValue = "sing gift loud head eagle fame produce tag atom comic picnic turkey bus lottery often choose regret time render duck fabric video matrix fortune";
    REQUIRE( mnemonic == mnemonicRealValue );
}