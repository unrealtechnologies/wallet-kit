//
// Created by Ariel Saldana on 4/4/23.
//

#include <catch2/catch_test_macros.hpp>
#include "utils.h"
#include "wallet-kit/bip39.h"
#include "wallet-kit/bip32.h"

SCENARIO("We test the BIP32 test vector 3", "[bip32testvec3]") {
    GIVEN("We have a BIP32 test vector 3") {
        WHEN("We run the test with seed (hex): 4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be") {
            std::string seedHexStr = "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be";
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
                        "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6");

                REQUIRE(
                        rootPublicExtendedKey.toBase58() ==
                        "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13");
            }

            THEN("We should get the expected result for chain m/0'") {
                auto keyTuple = rootChainNode->derivePath("m/0'");
                auto privateKey = std::get<0>(keyTuple);
                auto publicKey = std::get<1>(keyTuple);
                REQUIRE(
                        privateKey.toBase58() ==
                        "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L");

                REQUIRE(
                        publicKey.toBase58() ==
                        "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y");
            }
        }
    }
}
