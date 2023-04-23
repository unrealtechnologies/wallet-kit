//
// Created by Ariel Saldana on 4/4/23.
//

#include <catch2/catch_test_macros.hpp>
#include "wallet-kit/utils.h"
#include "wallet-kit/bip44.h"
#include "wallet-kit/coin_type.h"
#include <wallet-kit/bip39.h>
#include <wallet-kit/bip32.h>
#include <iomanip>
#include <algorithm>

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

            const auto path = bip44.generatePath(0);
            REQUIRE(path == "m/44'/60'/0'/0/0");

            auto keyTuple = rootChainNode->derivePath(path);
            THEN("We should get the expected result") {
                auto privateKey = std::get<0>(keyTuple);
                auto publicKey = std::get<1>(keyTuple);

                REQUIRE(
                        WalletKitUtils::toHex(publicKey.key, publicKey.key.size()) ==
                        "03bd0d889494ea14416805fc2ac543a284569e1191099f941e513720df9e9e39c8"
                );

                REQUIRE(
                        privateKey.toBase58() ==
                        "xprvA4AaGn74pfzyKs2Mq2Pb2ttyYyxyrDconFS9Dznj9NcxBYBc1i4FDMN5Tr4BWMzNDtYBMyMU2ZMYMdsQQ2K9m2CDyaLknp3sQsnTWwbKVDZ");

                REQUIRE(
                        publicKey.toBase58() ==
                        "xpub6H9vgHdxf3ZGYM6pw3vbQ2qi71oUFgLf9UMk2PCLhi9w4LWkZFNVm9gZK9msi9U1AiX4yfJUoerdVdwnUUW4RcSjjkBhPSp3ggKE9FHDsUc");


                auto addressIndex0 = privateKey.deriveAddress();
                REQUIRE(
                        addressIndex0 ==
                        "0x9e748224507f4b015CEE74EFa0DF4651AAe297e3");
            }
        }
    }
}

