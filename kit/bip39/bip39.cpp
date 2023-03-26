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

const size_t singleByteSize = 1U;

void combineArrays(const uint8_t *array1, size_t array1Size,
                   const uint8_t *array2, size_t array2Size,
                   uint8_t *combinedArray, size_t combinedArraySize) {
    if (combinedArraySize < array1Size + array2Size) {
        throw std::invalid_argument("Combined array size is too small.");
    }

    // Copy the first array to the beginning of the combined array
    std::copy(array1, array1 + array1Size, combinedArray);

    // Copy the second array to the end of the first array in the combined array
    std::copy(array2, array2 + array2Size, combinedArray + array1Size);
}

std::string Bip39::generateSeedWithEntropy(uint8_t *entropy, const size_t len) {
    if (len != 16U && len != 32U) {
        std::cout << "Error: length of entropy must be 16 or 32 bytes" << std::endl;
    }

    std::cout << to_hex(entropy, 32) << std::endl;

    // Get copy checksum value to checksum
    uint8_t checksum[singleByteSize];
    deriveChecksumRaw(entropy, len, checksum);

    // calculate the checksum length
    auto checksumBitsLength = len / (len / sizeof(size_t));

    // fullEntropy
    uint8_t fullEntropy[len + singleByteSize];
    combineArrays(
            entropy,
            len,
            checksum,
            singleByteSize,
            fullEntropy,
            len +
            singleByteSize
    );

    auto finalLen = (len * sizeof(size_t)) + checksumBitsLength;
    auto fullEntropyBits = charArrayToBinary(fullEntropy, len + singleByteSize, finalLen);

    if (fullEntropyBits.length() % 11 != 0) {
        std::cout << "ERROR with entropy string w/ checksum" << std::endl;
    }

    auto mnemonic = getWordsStringFromEntropyBits(fullEntropyBits);

    uint8_t bip39Seed[64];
    Bip39::generateBip39SeedFromMnemonic(mnemonic, bip39Seed);

    return to_hex(bip39Seed, 64U);
}

void Bip39::generateBip39SeedFromMnemonic(const std::string &mnemonic, uint8_t* bip39Seed) {
    std::vector<uint8_t> password(mnemonic.begin(), mnemonic.end());
    size_t passwordLength = mnemonic.length();
    const auto *salt = reinterpret_cast<const uint8_t *>("mnemonic");
    size_t saltLength = strlen("mnemonic");
    uint32_t iterations = 2048U;

    fastpbkdf2_hmac_sha512(&password[0], passwordLength, salt, saltLength, iterations, bip39Seed, 64U);
}

std::string Bip39::getWordsStringFromEntropyBits(const std::string &fullEntropyString) {
    auto wordsBinaryArr = split(fullEntropyString, 11);

    std::stringstream seedStringStream;
    for (std::string const &binaryString: wordsBinaryArr) {
        auto intValue = stoi(binaryString, nullptr, 2);
        seedStringStream << EnglishWordList[intValue] << " ";
    }

    std::string mnemonic = seedStringStream.str();

    std::cout << "mnemonic: " << mnemonic << std::endl;

    // remove the last space
    mnemonic.pop_back();
    return mnemonic;
}

uint8_t *Bip39::generateSeedWithEntropyRaw(uint8_t *entropy, size_t len) {
    if (len != 16U && len != 32U) {
        std::cout << "Error: length of entropy must be 16 or 32 bytes" << std::endl;
    }

    // Get copy checksum value to checksum
    uint8_t checksum[singleByteSize];
    deriveChecksumRaw(entropy, len, checksum);

    // calculate the checksum length
    auto checksumBitsLength = len / (len / sizeof(size_t));

    // fullEntropy
    uint8_t fullEntropy[len + singleByteSize];
    combineArrays(
            entropy,
            len,
            checksum,
            singleByteSize,
            fullEntropy,
            len +
            singleByteSize
    );

    auto finalLen = (len * sizeof(size_t)) + checksumBitsLength;
    auto fullEntropyBits = charArrayToBinary(fullEntropy, len + singleByteSize, finalLen);

    if (fullEntropyBits.length() % 11 != 0) {
        std::cout << "ERROR with entropy string w/ checksum" << std::endl;
    }

    auto mnemonic = getWordsStringFromEntropyBits(fullEntropyBits);

    uint8_t *bip39Seed = new uint8_t[64];
    Bip39::generateBip39SeedFromMnemonic(mnemonic, bip39Seed);

    return bip39Seed;
}




