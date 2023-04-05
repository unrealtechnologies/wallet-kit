//
// Created by Ariel Saldana on 4/4/23.
//

#include <catch2/catch_test_macros.hpp>
#include "utils.h"
#include "wallet-kit/bip39.h"
#include "wallet-kit/bip32.h"

SCENARIO("We test the BIP32 test vector 2", "[bip32testvec2]") {
    GIVEN("We have a BIP32 test vector 2") {
        WHEN("We run the test with seed (hex): fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542") {
            std::string seedHexStr = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
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
                        "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U");

                REQUIRE(
                        rootPublicExtendedKey.toBase58() ==
                        "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB");
            }

            THEN("We should get the expected result for chain m/0") {
                auto keyTuple = rootChainNode->derivePath("m/0");
                auto privateKey = std::get<0>(keyTuple);
                auto publicKey = std::get<1>(keyTuple);
                REQUIRE(
                        privateKey.toBase58() ==
                        "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt");

                REQUIRE(
                        publicKey.toBase58() ==
                        "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH");
            }

            THEN("We should get the expected result for chain m/0/2147483647H") {
                auto keyTuple = rootChainNode->derivePath("m/0/2147483647'");
                auto privateKey = std::get<0>(keyTuple);
                auto publicKey = std::get<1>(keyTuple);
                REQUIRE(
                        privateKey.toBase58() ==
                        "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9");

                REQUIRE(
                        publicKey.toBase58() ==
                        "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a");
            }

            THEN("We should get the expected result for chain m/0/2147483647H/1") {
                auto keyTuple = rootChainNode->derivePath("m/0/2147483647'/1");
                auto privateKey = std::get<0>(keyTuple);
                auto publicKey = std::get<1>(keyTuple);
                REQUIRE(
                        privateKey.toBase58() ==
                        "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef");

                REQUIRE(
                        publicKey.toBase58() ==
                        "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon");
            }

            THEN("We should get the expected result for chain m/0/2147483647H/1/2147483646H") {
                auto keyTuple = rootChainNode->derivePath("m/0/2147483647'/1/2147483646'");
                auto privateKey = std::get<0>(keyTuple);
                auto publicKey = std::get<1>(keyTuple);
                REQUIRE(
                        privateKey.toBase58() ==
                        "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc");

                REQUIRE(
                        publicKey.toBase58() ==
                        "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL");
            }

            THEN("We should get the expected result for chain m/0/2147483647H/1/2147483646H/2") {
                auto keyTuple = rootChainNode->derivePath("m/0/2147483647'/1/2147483646'/2");
                auto privateKey = std::get<0>(keyTuple);
                auto publicKey = std::get<1>(keyTuple);
                REQUIRE(
                        privateKey.toBase58() ==
                        "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j");

                REQUIRE(
                        publicKey.toBase58() ==
                        "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt");
            }

//            THEN("We should get the expected result for chain m/0H/1H") {
//                auto keyTuple = rootChainNode->derivePath("m/0'/1'");
//                auto privateKey = std::get<0>(keyTuple);
//                auto publicKey = std::get<1>(keyTuple);
//                REQUIRE(
//                        privateKey.toBase58() ==
//                        "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1");
//
//                REQUIRE(
//                        publicKey.toBase58() ==
//                        "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt");
//            }
        }
    }
}
