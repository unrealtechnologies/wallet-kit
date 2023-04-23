//
// Created by Ariel Saldana on 4/4/23.
//
#include <catch2/catch_test_macros.hpp>
#include "wallet-kit/utils.h"
#include "wallet-kit/bip39.h"

SCENARIO("We want to validate a bip39 mnemonic", "[bip39mnemonicvalidate]") {
    GIVEN("We have the mnemonic") {
        auto delimiter = " ";
        WHEN("We check with a valid mnemonic") {
            std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

            auto words = WalletKitUtils::split(mnemonic, delimiter);
            auto wordsIndexes = Bip39::seedStringToWordIndexVector(words);
            REQUIRE(wordsIndexes.size() == 12);
            auto isMnemonicValid = Bip39::validateMnemonic(mnemonic);
            REQUIRE(isMnemonicValid == true);
        }

        WHEN("We check with a invalid mnemonic") {
            std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

            auto words = WalletKitUtils::split(mnemonic, delimiter);
            auto wordsIndexes = Bip39::seedStringToWordIndexVector(words);
            REQUIRE(wordsIndexes.size() == 12);
            auto isMnemonicValid = Bip39::validateMnemonic(mnemonic);
            REQUIRE(isMnemonicValid == false);
        }
    }
}

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

        WHEN("We run the test with (entropy): ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff") {
            std::string entropyHexStr = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote");
            }
        }

        WHEN("We run the test with (entropy): 9e885d952ad362caeb4efe34a8e91bd2") {
            std::string entropyHexStr = "9e885d952ad362caeb4efe34a8e91bd2";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic");
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

        WHEN("We run the test with (entropy): 6610b25967cdcca9d59875f5cb50b0ea75433311869e930b") {
            std::string entropyHexStr = "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog");
            }
        }

        WHEN("We run the test with (entropy): 68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c") {
            std::string entropyHexStr = "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length");
            }
        }

        WHEN("We run the test with (entropy): c0ba5a8e914111210f2bd131f3d5e08d") {
            std::string entropyHexStr = "c0ba5a8e914111210f2bd131f3d5e08d";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "scheme spot photo card baby mountain device kick cradle pact join borrow");
            }
        }

        WHEN("We run the test with (entropy): 6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3") {
            std::string entropyHexStr = "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave");
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

        WHEN("We run the test with (entropy): 9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863") {
            std::string entropyHexStr = "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside");
            }
        }

        WHEN("We run the test with (entropy): 23db8160a31d3e0dca3688ed941adbf3") {
            std::string entropyHexStr = "23db8160a31d3e0dca3688ed941adbf3";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "cat swing flag economy stadium alone churn speed unique patch report train");
            }
        }

        WHEN("We run the test with (entropy): 8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0") {
            std::string entropyHexStr = "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access");
            }
        }

        WHEN("We run the test with (entropy): 066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad") {
            std::string entropyHexStr = "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform");
            }
        }

        WHEN("We run the test with (entropy): f30f8c1da665478f49b001d94c5fc452") {
            std::string entropyHexStr = "f30f8c1da665478f49b001d94c5fc452";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "vessel ladder alter error federal sibling chat ability sun glass valve picture");
            }
        }

        WHEN("We run the test with (entropy): c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05") {
            std::string entropyHexStr = "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump");
            }
        }

        WHEN("We run the test with (entropy): f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f") {
            std::string entropyHexStr = "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f";
            std::vector<uint8_t> entropyBytes = WalletKitUtils::hexStringToBytes(entropyHexStr);
            auto mnemonic = Bip39::entropyToMnemonic(entropyBytes);

            THEN("We the mnemonic should be generated correctly") {
                REQUIRE(mnemonic ==
                        "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold");
            }
        }
    }
}
