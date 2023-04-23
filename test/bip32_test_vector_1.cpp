//
// Created by Ariel Saldana on 4/4/23.
//

#include <catch2/catch_test_macros.hpp>
#include "wallet-kit/utils.h"
#include "wallet-kit/bip39.h"
#include "wallet-kit/bip32.h"

SCENARIO("We test the BIP32 test vector 1", "[bip32testvec1]") {
    GIVEN("We have a BIP32 test vector 1") {
        WHEN("We run the test with seed (hex): 000102030405060708090a0b0c0d0e0f") {
            std::string seedHexStr = "000102030405060708090a0b0c0d0e0f";
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
                        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");

                REQUIRE(
                        rootPublicExtendedKey.toBase58() ==
                        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
            }

            THEN("We should get the expected result for chain m/0H") {
                auto keyTuple = rootChainNode->derivePath("m/0'");
                auto privateKey = std::get<0>(keyTuple);
                auto publicKey = std::get<1>(keyTuple);
                REQUIRE(
                        privateKey.toBase58() ==
                        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7");

                REQUIRE(
                        publicKey.toBase58() ==
                        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw");
            }

            THEN("We should get the expected result for chain m/0H/1") {
                auto keyTuple = rootChainNode->derivePath("m/0'/1");
                auto privateKey = std::get<0>(keyTuple);
                auto publicKey = std::get<1>(keyTuple);
                REQUIRE(
                        privateKey.toBase58() ==
                        "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs");

                REQUIRE(
                        publicKey.toBase58() ==
                        "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ");
            }

            THEN("We should get the expected result for chain m/0H/1/2H") {
                auto keyTuple = rootChainNode->derivePath("m/0'/1/2'");
                auto privateKey = std::get<0>(keyTuple);
                auto publicKey = std::get<1>(keyTuple);
                REQUIRE(
                        privateKey.toBase58() ==
                        "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM");

                REQUIRE(
                        publicKey.toBase58() ==
                        "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5");
            }

            THEN("We should get the expected result for chain m/0'/1/2'/2") {
                auto keyTuple = rootChainNode->derivePath("m/0'/1/2'/2");
                auto privateKey = std::get<0>(keyTuple);
                auto publicKey = std::get<1>(keyTuple);
                REQUIRE(
                        privateKey.toBase58() ==
                        "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334");

                REQUIRE(
                        publicKey.toBase58() ==
                        "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV");
            }

            THEN("We should get the expected result for chain m/0H/1/2H/2/1000000000") {
                auto keyTuple = rootChainNode->derivePath("m/0'/1/2'/2/1000000000");
                auto privateKey = std::get<0>(keyTuple);
                auto publicKey = std::get<1>(keyTuple);
                REQUIRE(
                        privateKey.toBase58() ==
                        "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76");

                REQUIRE(
                        publicKey.toBase58() ==
                        "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy");
            }
        }
    }
}
