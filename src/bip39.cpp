//
// Created by Ariel Saldana on 3/26/23.
//
#include <iostream>
#include "wallet-kit/utils.h"
#include "wallet-kit/bip39.h"
#include "wallet-kit/english_wordlist.h"
#include "wallet-kit/crypto_utils.h"
#include <botan/pbkdf2.h>
#include <botan/mac.h>
#include <botan/types.h>
#include <sstream>

std::string Bip39::entropyToMnemonic(std::vector<uint8_t> &entropy) {
    if (entropy.size() < entropyBytesMinLength ||
        entropy.size() > entropyBytesMaxLength ||
        entropy.size() % mnemonicWordGroupSize != 0) {
        throw std::runtime_error("Key size should be between 128 and 256 bits");
    }

    auto checksum = getEntropyChecksum(entropy);
    auto checksumBinary = WalletKitUtils::vecToBinaryString(checksum);
    auto checksumLength = entropy.size() * bitsInByte / mnemonicEncodeBitsSize;

    auto fullEntropyBinaryString = WalletKitUtils::vecToBinaryString(entropy);
    fullEntropyBinaryString += checksumBinary.substr(0, checksumLength);

    if (fullEntropyBinaryString.length() % Bip39::numberOfBitsPerWord != 0) {
        throw std::runtime_error("Error with entropy string + checksum");
    }

    return fullEntropyBitsToMnemonicWords(fullEntropyBinaryString);
}

std::vector<uint8_t> Bip39::mnemonicToSeed(const std::string &mnemonic) {
    return mnemonicToSeed(mnemonic, "");
}

std::vector<uint8_t> Bip39::mnemonicToSeed(std::string mnemonic, const std::string &passphrase) {
    // Define the password and salt to use
    std::string salt = "mnemonic";
    salt += passphrase;

    // Define the number of iterations to use
    const size_t iterations = 2048;

    // Define the output length of the key (in bytes)
    const size_t outputLength = 64;

    // Define the PRF to use (in this case, HMAC-SHA-512)
    std::unique_ptr<Botan::MessageAuthenticationCode> prf(Botan::MessageAuthenticationCode::create("HMAC(SHA-512)"));
    std::vector<uint8_t> password(mnemonic.begin(), mnemonic.end());
    prf->set_key(password);

    // make the output buffer twice the length of the output.
    uint8_t out[outputLength * 2];

    const auto *saltUint8 = reinterpret_cast<const uint8_t *>(salt.c_str());

    Botan::pbkdf2(*prf,
                  out, outputLength,
                  saltUint8, salt.length(),
                  iterations);

    std::vector<uint8_t> seed(out, out + outputLength);
    return seed;
}


std::string Bip39::fullEntropyBitsToMnemonicWords(const std::string &fullEntropyString) {
    auto wordsBinaryArr = WalletKitUtils::split(fullEntropyString, Bip39::numberOfBitsPerWord);

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

std::vector<uint8_t> Bip39::getEntropyChecksum(std::vector<uint8_t> &entropy) {
    return WalletKitCryptoUtils::sha256(entropy);
}

bool Bip39::validateMnemonic(const std::string &mnemonic) {
    auto words = WalletKitUtils::split(mnemonic, " ");
    auto wordsIndexes = seedStringToWordIndexVector(words);

    if (words.size() != wordsIndexes.size()) {
        return false;
    }

    if (words.size() < minMnemonicWords ||
        words.size() > maxMnemonicWords ||
        words.size() % mnemonicWordGroupSize != 0) {
        return false;
    }

    // calculate the checksum length
    const auto fullEntropyLength = words.size() * numberOfBitsPerWord;
    const auto checksumLength = fullEntropyLength % 8 == 0 ? 8 : fullEntropyLength % 8;

    // turn the indexes back to 11 bits and appends it to a string
    std::ostringstream oss;
    for (const auto &index: wordsIndexes) {
        oss << WalletKitUtils::uint16ToBinary(index, numberOfBitsPerWord);
    }
    const auto bits = oss.str();
    const auto entropyBits = bits.substr(0, bits.length() - checksumLength);
    const auto checksumBits = bits.substr(bits.length() - 4, bits.length());

    // reconstruct to bytes
    std::vector<uint8_t> entropyBytes;
    for (size_t i = 0; i < entropyBits.size(); i += 8) {
        std::string bitsString = entropyBits.substr(i, 8);
        auto byte = static_cast<uint8_t>(std::stoi(bitsString, nullptr, 2));
        entropyBytes.push_back(byte);
    }

    // sha256 the bytes, the first n (checksumLength) of the hash should match the input checksum
    auto digest = WalletKitCryptoUtils::sha256(entropyBytes);
    auto digestChecksum = WalletKitUtils::vecToBinaryString(digest).substr(0, checksumLength);

    if (digestChecksum == checksumBits) {
        return true;
    }

    return false;
}

std::vector<uint16_t> Bip39::seedStringToWordIndexVector(const std::vector<std::string> &words) {
    std::vector<uint16_t> wordListIndexes;
    for (const auto &word: words) {
        for (uint16_t i = 0; i < 2048; i++) {
            if (word == EnglishWordList[i]) {
                wordListIndexes.push_back(i);
                continue;
            }
        }
    }
    return wordListIndexes;
}
