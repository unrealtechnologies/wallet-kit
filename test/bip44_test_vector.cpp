//
// Created by Ariel Saldana on 4/4/23.
//

#include <catch2/catch_test_macros.hpp>
#include "utils.h"
#include <wallet-kit/bip44/bip44.h>
#include <wallet-kit/bip44/coin_type.h>
#include <wallet-kit/bip39.h>
#include <wallet-kit/bip32.h>

TEST_CASE("Bip44 paths are generated correctly", "[generatePath]") {
    GIVEN("We have a Bip44 object") {
        Bip44 bip44(CoinType::ETH, 0, 0);
        WHEN("We generate a path") {
            THEN("We should get the expected path") {
                REQUIRE(bip44.generatePath(0) == "m/44'/60'/0'/0/0");
            }
        }
    }
}

SCENARIO("With Bip44 Paths we can derive keys", "[generatePath&DeriveKeys]") {

    GIVEN("That we generated a bip32 root node from a seed") {

        std::string seedHexStr = "8b3d3c2f07e8eefee19f3426607d4ed156aac2c3362a05746827c85954e60a10ae78b5a04c195ebbd53e2abb34c3d4989fd635c7dd1c151f6a7c16439a6c9dda";
        auto seed = WalletKitUtils::hexStringToBytes(seedHexStr);
        auto rootChainNode = Bip32::fromSeed(seed);
        auto rootChainNodeKeys = rootChainNode->indexes.find(0x80000000);
        ExtendedKey rootPrivateExtendedKey = *std::get<0>(rootChainNodeKeys->second);
        ExtendedKey rootPublicExtendedKey = *std::get<1>(rootChainNodeKeys->second);

        WHEN("We derive a key from bip44 path: m/44'/60'/0'/0/0 (account 0)") {

            Bip44 bip44(CoinType::ETH, 0, 0);
            std::cout << bip44.generatePath(0) <<std::endl;
            auto keyTuple = rootChainNode->derivePath(bip44.generatePath(0));

            THEN("We should get the expected result") {
                auto privateKey = std::get<0>(keyTuple);
                auto publicKey = std::get<1>(keyTuple);
                REQUIRE(
                        privateKey.toBase58() ==
                        "xprvA4AaGn74pfzyKs2Mq2Pb2ttyYyxyrDconFS9Dznj9NcxBYBc1i4FDMN5Tr4BWMzNDtYBMyMU2ZMYMdsQQ2K9m2CDyaLknp3sQsnTWwbKVDZ");

                REQUIRE(
                        publicKey.toBase58() ==
                        "xpub6H9vgHdxf3ZGYM6pw3vbQ2qi71oUFgLf9UMk2PCLhi9w4LWkZFNVm9gZK9msi9U1AiX4yfJUoerdVdwnUUW4RcSjjkBhPSp3ggKE9FHDsUc");
            }
        }
    }
}

