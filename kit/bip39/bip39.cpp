//
// Created by Ariel Saldana on 3/24/23.
//

#include "bip39.h"
#include "wordlist.h"
#include "generate_entropy.h"
#include "to_binary.h"
#include "derive_checksum_bits.h"
#include "to_hex.h"
#include "split.h"
#include "../../third-party/duthomhas/csprng.hpp"
#include "../../third-party/fastpbkdf2/fastpbkdf2.h"

std::string Bip39::generateSeedWithEntropy(uint8_t *entropy) {
    auto checksumBits = deriveChecksumBits(entropy, 32);

    auto entropyBits = char_array_to_binary(entropy, 32);

    if (entropyBits.length() != 256) {
        std::cout << "ERROR with BINARY" << std::endl;
    }
    auto fullEntropyString = entropyBits + checksumBits;

    if (fullEntropyString.length() % 11 != 0) {
        std::cout << "ERROR with entropy string w/ checksum" << std::endl;
    }

    auto mnemonic = getWordsFromEntropyBinary(fullEntropyString);

    const auto *pw = (const uint8_t *) reinterpret_cast<const uint8_t *>(mnemonic.data());
    size_t npw = mnemonic.length();
    const auto *salt = (const uint8_t *) "mnemonic";
    size_t saltLen = strlen("mnemonic");
    uint32_t iterations = 2048;
    uint8_t bip39Seed[64];

    fastpbkdf2_hmac_sha512(pw, npw, salt, saltLen, iterations, bip39Seed, sizeof(bip39Seed));

    return to_hex(bip39Seed, 64);
}

std::string Bip39::getWordsFromEntropyBinary(const std::string &fullEntropyString) {
    auto wordsBinaryArr = split(fullEntropyString, 11);

    std::stringstream seedStringStream;
    for (std::string const &binaryString: wordsBinaryArr) {
        auto intValue = stoi(binaryString, nullptr, 2);
        seedStringStream << EnglishWordList[intValue] << " ";
    }

    std::string mnemonic = seedStringStream.str();

    // remove the last space
    mnemonic.pop_back();
    return mnemonic;
}