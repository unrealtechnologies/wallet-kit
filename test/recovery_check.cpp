
//
// Created by Ariel Saldana on 4/4/23.
//

#include <catch2/catch_test_macros.hpp>
#include "wallet-kit/utils.h"
#include "wallet-kit/bip44.h"
#include "wallet-kit/coin_type.h"
#include <wallet-kit/bip39.h>
#include <wallet-kit/bip32.h>
#include <algorithm>

SCENARIO("With Bip44 Paths we can derive keys with Password", "[generatePath&DeriveKeys2]") {

    GIVEN("That we generated a bip32 root node from a seed") {
        std::string mnemonic = "sing gift loud head eagle fame produce tag atom comic picnic turkey bus lottery often choose regret time render duck fabric video matrix fortune";
        auto seed = Bip39::mnemonicToSeed(mnemonic, "meow");

        REQUIRE(WalletKitUtils::toHex(seed, seed.size()) == "df5833e3ddb657b0814b15b75e3c1975b7bed91ec92b95d067052ee49bcd6c352d6eb03d25697c45aa8a45074bc897ad991b482015e9f6683b7b63372ec9d083");
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
                        privateKey.toBase58() ==
                        "xprvA3sFokCmXomABhv5tFsTS6aoA4tep2DNxDoAPvBEWpikKN6YVwqxXHBCsVa4cvrcW33fSMMHLKe1afnFKB6ShKapNG91HqHpS94xVqNUQ8W");
                REQUIRE(
                        publicKey.toBase58() ==
                        "xpub6GrcDFjfNBKTQBzYzHQToEXXi6j9DUwEKSimCJar5AFjCARh3VAD55Vgin7WyHwoKVYYoGRAMJfX7K95f2BDzJbr9fmoXW6VcdkUehP2xQC");

            }
        }
    }
}


