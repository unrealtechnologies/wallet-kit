//
// Created by Ariel Saldana on 3/24/23.
//

#include "bip39.h"
#include "./wordlist.h"
#include "generate_entropy.h"
#include "to_binary.h"
#include "derive_checksum_bits.h"
#include "to_hex.h"
#include "split.h"
#include "../../third-party/duthomhas/csprng.hpp"
#include "../../third-party/fastpbkdf2/fastpbkdf2.h"

std::string Bip39::generateSeedWithEntropy(uint8_t* entropy) {
    auto entropyBits = char_array_to_binary(entropy, 32);

    if (entropyBits.length() != 256) {
        std::cout << "ERROR with BINARY" << std::endl;
    }
    auto checksumBinary = derive_checksum_bits(entropy, 32);
    auto full_entropy_string = entropyBits + checksumBinary;

    if ( full_entropy_string.length() % 11 != 0 ) {
        std::cout << "ERROR with entropy string w/ checksum" << std::endl;
    }

    auto mnemonic = getWordsFromEntropyBinary(full_entropy_string);

    const auto *pw = (const uint8_t *)reinterpret_cast<const uint8_t*>(mnemonic.data());
    size_t npw = mnemonic.length();
    const auto *salt = (const uint8_t *)"mnemonic";
    size_t nsalt = strlen("mnemonic");
    uint32_t iterations = 2048;
    uint8_t bip39seed[64];

    fastpbkdf2_hmac_sha512(pw, npw, salt, nsalt, iterations, bip39seed, sizeof(bip39seed));

    return to_hex(bip39seed, 64);
}

std::string Bip39::getWordsFromEntropyBinary(const std::string& full_entropy_string) {
    auto words_binary_arr = split(full_entropy_string, 11);

    std::stringstream seed_string_stream;
    for (std::string const& binaryString: words_binary_arr) {
        auto int_value = stoi(binaryString, 0, 2);
        seed_string_stream << EnglishWordList[int_value] << " ";
    }

    std::string mnemonic = seed_string_stream.str();
    // remove the last space
    mnemonic.pop_back();
    return mnemonic;
}