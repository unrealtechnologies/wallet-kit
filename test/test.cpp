//
// Created by Ariel Saldana on 3/27/23.
//

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <wallet-kit/bip39.h>
#include <wallet-kit/bip32.h>
#include <utils.h>

TEST_CASE("Bip39 mnemonics are derived correctly", "[entropyToMnemonic]") {
    std::string entropyHexStr = "c94c3a10b50450a4eaeee90e45ca90f551ef08266942b4bc4ad821e517e7a24a";
    std::vector<uint8_t> entropyBytes = walletKitUtils::hexStringToBytes(entropyHexStr);
    auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);
    REQUIRE(mnemonic ==
            "sing gift loud head eagle fame produce tag atom comic picnic turkey bus lottery often choose regret time render duck fabric video matrix fortune");
}

TEST_CASE("Bip39 seed is derived correctly from mnemonic", "[entropyToMnemonic]") {
    std::string mnemonic = "sing gift loud head eagle fame produce tag atom comic picnic turkey bus lottery often choose regret time render duck fabric video matrix fortune";
    auto seed = Bip39::mnemonicToSeed(mnemonic);
    auto seedHex = walletKitUtils::to_hex(seed, 64);
    REQUIRE(seedHex ==
            "8b3d3c2f07e8eefee19f3426607d4ed156aac2c3362a05746827c85954e60a10ae78b5a04c195ebbd53e2abb34c3d4989fd635c7dd1c151f6a7c16439a6c9dda");
}

SCENARIO("main chain node can be created.") {
    GIVEN("A bip39 mnemonic") {
        std::string mnemonic = "sing gift loud head eagle fame produce tag atom comic picnic turkey bus lottery often choose regret time render duck fabric video matrix fortune";
        auto seed = Bip39::mnemonicToSeed(mnemonic);
        WHEN("A bip 39 seed is created") {
            THEN("The seed is 64 bytes") {
                REQUIRE(seed.size() == 64);
            }THEN("The seed is correct") {
                REQUIRE(walletKitUtils::to_hex(seed, seed.size()) ==
                        "8b3d3c2f07e8eefee19f3426607d4ed156aac2c3362a05746827c85954e60a10ae78b5a04c195ebbd53e2abb34c3d4989fd635c7dd1c151f6a7c16439a6c9dda");
            }
        }

        auto rootChainNode = Bip32::fromSeed(seed);
        auto rootPrivateExtendedKey = *rootChainNode->privateKey;
        auto rootPublicExtendedKey = *rootChainNode->publicKey;

        WHEN("A chain node is created from a bip39 seed") {
            THEN("Chain node local path is correct") {
                REQUIRE(rootChainNode->localPath == "m");
            }THEN("Chain node private key length is correct") {
                REQUIRE(rootPrivateExtendedKey.key.size() == 32);
            }THEN("Chain node private chain code length is correct") {
                REQUIRE(rootPrivateExtendedKey.chainCode.size() == 32);
            }THEN("Chain node private key is correct") {
                REQUIRE(
                        walletKitUtils::to_hex(rootPrivateExtendedKey.key, rootPrivateExtendedKey.key.size()) ==
                        "3f61cacd5557d1dfd98a363e0e1af2c91fd83cbd36ec2de9f14f2e2b00b3f09b");
            }THEN("Chain node private chain code is correct") {
                REQUIRE(walletKitUtils::to_hex(rootPrivateExtendedKey.chainCode,
                                               rootPrivateExtendedKey.chainCode.size()) ==
                        "7325025b59e91b0e0b774a2ea39dd059042682f2199557cb05af9752611f1a34");
            }THEN("Chain node public key length is correct") {
                REQUIRE(rootPublicExtendedKey.key.size() == 33);
            }THEN("Chain node public key is correct") {
                REQUIRE(walletKitUtils::to_hex(rootPublicExtendedKey.key, rootPublicExtendedKey.key.size()) ==
                        "031012b6a7b8e293198f9c798b8083c3e171cd0bdd42490d4b00995d4335cbe2f9");
            }
        }

        WHEN("A chain node private key is serialized to base58") {
            auto base58EncodedString = rootPrivateExtendedKey.toBase58();

            THEN("The base58 encoded string starts with xprv") {
                REQUIRE(base58EncodedString.substr(0, 4) == "xprv");
            }

            THEN("The base58 encoded string has a length less than 112") {
                REQUIRE(base58EncodedString.length() <= 112);
            }

            THEN("The base58 encoded string is correct") {
                REQUIRE(base58EncodedString ==
                        "xprv9s21ZrQH143K3Cr6tYyh5vEeD3SaGsKf3bqytbwfCZzw8QZFGufkaNVbGTg6MzFGkfPzMJa415XX7TUni8i3H84akgjG1i4YYavxQbq1krK");
            }
        }

        WHEN("A chain node public key is serialized to base58") {
            auto base58EncodedString = rootPublicExtendedKey.toBase58();

            THEN("The base58 encoded string starts with xpub") {
                REQUIRE(base58EncodedString.substr(0, 4) == "xpub");
            }

            THEN("The base58 encoded string has a length less than 112") {
                REQUIRE(base58EncodedString.length() <= 112);
            }

            THEN("The base58 encoded string is correct") {
                REQUIRE(base58EncodedString ==
                        "xpub661MyMwAqRbcFgvZzaWhT4BNm5H4gL3WQpmagzMGkuXv1CtPpSz18Ap57kHmYCZKuDNN5hdHzkanQY8DyjsPZAbZeNREkpX5DrZmXwS6QRb");
            }
        }

        WHEN("The root private key is used to derive a private key") {
//            auto privateExtendedKey = Bip32::derivePrivateChildKey(rootPrivateExtendedKey, 0, true);
            auto privateExtendedKey = rootChainNode->derivePrivateChildExtendedKey(true);

            THEN("The private key should be correct") {
                REQUIRE(walletKitUtils::to_hex(privateExtendedKey->key, 32) ==
                    "47ec40c7de9fd08fde2937c81b0f58c6de46c367a3e83e2c676d8f58e5254b77");
            }

            THEN("The chaincode should be correct") {
                REQUIRE(walletKitUtils::to_hex(privateExtendedKey->chainCode, 32) ==
                        "8c4c055d7c0cdf1b79678eaad92a83f6fe8049c7eb4ba088e0d8e49484e0abe1");
            }

            auto privateExtendedKeySerializedValue = privateExtendedKey->toBase58();
            THEN("The base58 encoded string is correct") {
                REQUIRE(privateExtendedKeySerializedValue ==
                        "xprv9uXf9j4vLU4LJ8uDsAWnECLm69qZo6rsGGHM5hrAfHsikZEkG6AQsVji64pdwMUom9bLbmCbb8ARBUdvqYu6GpwVoCmmZ6Jp6FUTskLZFgJ");
            }
        }
    }
}

TEST_CASE("Bip32 extended private key from Bip39 Seed", "[fromSeed]") {
    std::string mnemonic = "sing gift loud head eagle fame produce tag atom comic picnic turkey bus lottery often choose regret time render duck fabric video matrix fortune";
    auto seed = Bip39::mnemonicToSeed(mnemonic);
    auto rootChainNode = Bip32::fromSeed(seed);
    ExtendedKey rootPrivateExtendedKey = *rootChainNode->privateKey;
    ExtendedKey rootPublicExtendedKey = *rootChainNode->publicKey;

    REQUIRE(rootChainNode->localPath == "m");
    REQUIRE(
            walletKitUtils::to_hex(rootPrivateExtendedKey.key, 32) ==
            "3f61cacd5557d1dfd98a363e0e1af2c91fd83cbd36ec2de9f14f2e2b00b3f09b");
    REQUIRE(walletKitUtils::to_hex(rootPrivateExtendedKey.chainCode, 32) ==
            "7325025b59e91b0e0b774a2ea39dd059042682f2199557cb05af9752611f1a34");

    REQUIRE(walletKitUtils::to_hex(rootPublicExtendedKey.key, 33) ==
            "031012b6a7b8e293198f9c798b8083c3e171cd0bdd42490d4b00995d4335cbe2f9");
    REQUIRE(walletKitUtils::to_hex(rootPublicExtendedKey.chainCode, 32) ==
            "7325025b59e91b0e0b774a2ea39dd059042682f2199557cb05af9752611f1a34");

//    auto things = Bip32::derivePrivateChildKey(*rootPrivateExtendedKey, 0, true);
//    std::cout << things->toBase58() << std::endl;
}

//TEST_CASE( "Bip32 extended private key serializes to base58", "[fromSeed]" ) {
//    std::string mnemonic = "sing gift loud head eagle fame produce tag atom comic picnic turkey bus lottery often choose regret time render duck fabric video matrix fortune";
//    auto seed = Bip39::mnemonicToSeed(mnemonic);
//    auto rootExtendedKey = Bip32::fromSeed(seed);
//    auto base58EncodedString = rootExtendedKey->toBase58();
//    REQUIRE( base58EncodedString == "xprv9s21ZrQH143K3Cr6tYyh5vEeD3SaGsKf3bqytbwfCZzw8QZFGufkaNVbGTg6MzFGkfPzMJa415XX7TUni8i3H84akgjG1i4YYavxQbq1krK");
//}
//
//TEST_CASE( "Bip32 extended public key serializes to base58", "[fromSeed]" ) {
//    std::string mnemonic = "sing gift loud head eagle fame produce tag atom comic picnic turkey bus lottery often choose regret time render duck fabric video matrix fortune";
//    auto seed = Bip39::mnemonicToSeed(mnemonic);
//    auto rootExtendedKey = Bip32::fromSeed(seed);
//    auto rootPublicKey = Bip32::derivePublicChildKey(*rootExtendedKey);
//    auto base58EncodedString = rootPublicKey->toBase58();
//    REQUIRE( base58EncodedString == "xpub661MyMwAqRbcFgvZzaWhT4BNm5H4gL3WQpmagzMGkuXv1CtPpSz18Ap57kHmYCZKuDNN5hdHzkanQY8DyjsPZAbZeNREkpX5DrZmXwS6QRb");
//}