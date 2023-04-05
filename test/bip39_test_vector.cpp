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

        WHEN("We run the test with (entropy): 7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f") {
            std::string entropyHexStr = "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "legal winner thank year wave sausage worth useful legal winner thank yellow");
            }
        }

        WHEN("We run the test with (entropy): 80808080808080808080808080808080") {
            std::string entropyHexStr = "80808080808080808080808080808080";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above");
            }
        }

        WHEN("We run the test with (entropy): ffffffffffffffffffffffffffffffff") {
            std::string entropyHexStr = "ffffffffffffffffffffffffffffffff";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");
            }
        }

        WHEN("We run the test with (entropy): 000000000000000000000000000000000000000000000000") {
            std::string entropyHexStr = "000000000000000000000000000000000000000000000000";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent");
            }
        }

        WHEN("We run the test with (entropy): 7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f") {
            std::string entropyHexStr = "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will");
            }
        }

        WHEN("We run the test with (entropy): 808080808080808080808080808080808080808080808080") {
            std::string entropyHexStr = "808080808080808080808080808080808080808080808080";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always");
            }
        }

        WHEN("We run the test with (entropy): ffffffffffffffffffffffffffffffffffffffffffffffff") {
            std::string entropyHexStr = "ffffffffffffffffffffffffffffffffffffffffffffffff";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when");
            }
        }

        WHEN("We run the test with (entropy): 0000000000000000000000000000000000000000000000000000000000000000") {
            std::string entropyHexStr = "0000000000000000000000000000000000000000000000000000000000000000";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art");
            }
        }

        WHEN("We run the test with (entropy): 7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f") {
            std::string entropyHexStr = "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title");
            }
        }

        WHEN("We run the test with (entropy): 8080808080808080808080808080808080808080808080808080808080808080") {
            std::string entropyHexStr = "8080808080808080808080808080808080808080808080808080808080808080";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless");
            }
        }

//        WHEN("We run the test with (entropy): 000000000000000000000000000000000000000000000000") {
//            std::string entropyHexStr = "000000000000000000000000000000000000000000000000";
//            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
//            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);
//
//            THEN("We the mnemonic should be generated correctly") {
//                REQUIRE(mnemonic ==
//                        "");
//            }
//        }
    }
}
