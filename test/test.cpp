//
// Created by Ariel Saldana on 3/27/23.
//

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <wallet-kit/bip39.h>
#include <wallet-kit/bip32.h>
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

TEST_CASE( "Bip32 extended private key from Bip39 Seed", "[fromSeed]" ) {
    std::string mnemonic = "sing gift loud head eagle fame produce tag atom comic picnic turkey bus lottery often choose regret time render duck fabric video matrix fortune";
    auto seed = Bip39::mnemonicToSeed(mnemonic);
    auto rootExtendedKey = Bip32::fromSeed(seed);
    REQUIRE( walletKitUtils::to_hex(rootExtendedKey->key, 32) == "3f61cacd5557d1dfd98a363e0e1af2c91fd83cbd36ec2de9f14f2e2b00b3f09b");
    REQUIRE( walletKitUtils::to_hex(rootExtendedKey->chainCode, 32) == "7325025b59e91b0e0b774a2ea39dd059042682f2199557cb05af9752611f1a34");
}

TEST_CASE( "Bip32 extended public key from Bip39 Seed", "[derivePublicChildKey]" ) {
    std::string mnemonic = "sing gift loud head eagle fame produce tag atom comic picnic turkey bus lottery often choose regret time render duck fabric video matrix fortune";
    auto seed = Bip39::mnemonicToSeed(mnemonic);
    auto rootExtendedKey = Bip32::fromSeed(seed);
    auto rootPublicKey = Bip32::derivePublicChildKey(*rootExtendedKey);

    REQUIRE( walletKitUtils::to_hex(rootPublicKey->key, 33) == "031012b6a7b8e293198f9c798b8083c3e171cd0bdd42490d4b00995d4335cbe2f9");
    REQUIRE( walletKitUtils::to_hex(rootPublicKey->chainCode, 32) == "7325025b59e91b0e0b774a2ea39dd059042682f2199557cb05af9752611f1a34");
}


TEST_CASE( "Bip32 extended private key serializes to base58", "[fromSeed]" ) {
    std::string mnemonic = "sing gift loud head eagle fame produce tag atom comic picnic turkey bus lottery often choose regret time render duck fabric video matrix fortune";
    auto seed = Bip39::mnemonicToSeed(mnemonic);
    auto rootExtendedKey = Bip32::fromSeed(seed);
    auto base58EncodedString = rootExtendedKey->toBase58();
    REQUIRE( base58EncodedString == "xprv9s21ZrQH143K3Cr6tYyh5vEeD3SaGsKf3bqytbwfCZzw8QZFGufkaNVbGTg6MzFGkfPzMJa415XX7TUni8i3H84akgjG1i4YYavxQbq1krK");
}

TEST_CASE( "Bip32 extended public key serializes to base58", "[fromSeed]" ) {
    std::string mnemonic = "sing gift loud head eagle fame produce tag atom comic picnic turkey bus lottery often choose regret time render duck fabric video matrix fortune";
    auto seed = Bip39::mnemonicToSeed(mnemonic);
    auto rootExtendedKey = Bip32::fromSeed(seed);
    auto rootPublicKey = Bip32::derivePublicChildKey(*rootExtendedKey);
    auto base58EncodedString = rootPublicKey->toBase58();
    REQUIRE( base58EncodedString == "xpub661MyMwAqRbcFgvZzaWhT4BNm5H4gL3WQpmagzMGkuXv1CtPpSz18Ap57kHmYCZKuDNN5hdHzkanQY8DyjsPZAbZeNREkpX5DrZmXwS6QRb");
}