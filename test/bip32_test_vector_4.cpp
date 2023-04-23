//
// Created by Ariel Saldana on 4/4/23.
//

#include <catch2/catch_test_macros.hpp>
#include "wallet-kit/utils.h"
#include "wallet-kit/bip39.h"
#include "wallet-kit/bip32.h"

SCENARIO("We test the BIP32 test vector 4", "[bip32testvec4]") {
    GIVEN("We have a BIP32 test vector 4") {
        WHEN("We run the test with seed (hex): 3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678") {
            std::string seedHexStr = "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678";
            auto seed = WalletKitUtils::hexStringToBytes(seedHexStr);
            auto rootChainNode = Bip32::fromSeed(seed);

            std::get<0>(rootChainNode->indexes.find(0x80000000)->second);
            std::get<1>(rootChainNode->indexes.find(0x80000000)->second);

            auto t = rootChainNode->indexes.find(0x80000000);
            ExtendedKey rootPrivateExtendedKey = *std::get<0>(t->second);
            ExtendedKey rootPublicExtendedKey = *std::get<1>(t->second);

            THEN("We should get the expected result for chain m") {
                REQUIRE(
                        rootPrivateExtendedKey.toBase58() ==
                        "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv");

                REQUIRE(
                        rootPublicExtendedKey.toBase58() ==
                        "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa");
            }

            THEN("We should get the expected result for chain m/0H") {
                auto keyTuple = rootChainNode->derivePath("m/0'");
                auto privateKey = std::get<0>(keyTuple);
                auto publicKey = std::get<1>(keyTuple);
                REQUIRE(
                        privateKey.toBase58() ==
                        "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G");

                REQUIRE(
                        publicKey.toBase58() ==
                        "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m");
            }

            THEN("We should get the expected result for chain m/0H/1H") {
                auto keyTuple = rootChainNode->derivePath("m/0'/1'");
                auto privateKey = std::get<0>(keyTuple);
                auto publicKey = std::get<1>(keyTuple);
                REQUIRE(
                        privateKey.toBase58() ==
                        "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1");

                REQUIRE(
                        publicKey.toBase58() ==
                        "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt");
            }
        }
    }
}
