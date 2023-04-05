//
// Created by Ariel Saldana on 4/4/23.
//

#include <catch2/catch_test_macros.hpp>
#include "utils.h"
#include "wallet-kit/bip39.h"
#include "wallet-kit/bip32.h"

SCENARIO("We test the BIP39 test vector", "[bip39testvec]") {
    GIVEN("We have a BIP39 test vector") {
        WHEN("We run the test with (entropy): 00000000000000000000000000000000") {
            std::string entropyHexStr = "00000000000000000000000000000000";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
            }
        }
    }
}
