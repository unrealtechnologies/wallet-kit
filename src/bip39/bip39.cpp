//
// Created by Ariel Saldana on 3/26/23.
//
#include <iostream>
#include <utils.h>
#include <wallet-kit/bip39.h>
#include <wallet-kit/bip39/english_wordlist.h>
#include <botan/hash.h>
#include <botan/pbkdf2.h>
#include <botan/mac.h>
#include <botan/types.h>
#include <sstream>

std::string Bip39::entropyToMnemonic(std::vector<uint8_t> &entropy) {
    if (entropy.size() < 16 || entropy.size() > 32 || entropy.size() % 4 != 0) {
        throw std::runtime_error("Key size should be between 128 and 256 bits");
    }

    auto checksum = getEntropyChecksum(entropy);
    auto checksumBinary = WalletKitUtils::vecToBinaryString(checksum);
    auto checksumLength = entropy.size() * 8 / 32;

    auto fullEntropyBinaryString = WalletKitUtils::vecToBinaryString(entropy);
    fullEntropyBinaryString += checksumBinary.substr(0, checksumLength);

    if (fullEntropyBinaryString.length() % Bip39::numberOfBitsPerWord != 0) {
        throw std::runtime_error("Error with entropy string + checksum");
    }

    return fullEntropyBitsToMnemonicWords(fullEntropyBinaryString);
}

std::vector<std::uint8_t> getBytes(std::string const &s)
{
    std::vector<std::uint8_t> bytes;
    bytes.reserve(s.size());

    std::transform(std::begin(s), std::end(s), std::back_inserter(bytes), [](char c){
        return std::uint8_t(c);
    });

    return bytes;
}

std::vector<uint8_t> Bip39::mnemonicToSeed(const std::string& mnemonic) {
    return mnemonicToSeed(mnemonic, "");
}

std::vector<uint8_t> Bip39::mnemonicToSeed(std::string mnemonic, const std::string& passphrase) {
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
                  iterations
    );

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
    std::unique_ptr<Botan::HashFunction> hash256(Botan::HashFunction::create("SHA-256"));

    hash256->update(entropy.data(), entropy.size());
    auto digest = hash256->final();
    auto hash = std::vector<uint8_t>(digest.begin(), digest.end());

    uint8_t checksum = hash[0];
    return std::vector<uint8_t>{checksum};
}

bool Bip39::validateMnemonic(const std::string &mnemonic) {
    auto delimiter = " ";
    auto wordVector = WalletKitUtils::split(mnemonic, delimiter);

    if (wordVector.size() > 24 || wordVector.size() < 12 || wordVector.size() % 2 != 0) {
        return false;
    }

    // if the entropy is 128 bits aka 16 bytes, how do we turn that into something we can verify.
    // the checksum length is the remainder of the length divided by 8. if 0 = 8
    const auto fullEntropyLength = wordVector.size() * numberOfBitsPerWord;
    const auto checksumLength = fullEntropyLength % 8 == 0 ? 8: fullEntropyLength % 8;

    std::cout << checksumLength << std::endl;
    std::cout << fullEntropyLength << std::endl;


    std::ostringstream oss;
    for (const auto &word: wordVector) {
        auto binaryStr = WalletKitUtils::strToBinaryString(word);
        oss << binaryStr.substr(0, numberOfBitsPerWord);
    }

    const auto finalChecksumBinaryString = oss.str();
    const auto entropyBinaryString = finalChecksumBinaryString.substr(0, finalChecksumBinaryString.size() - checksumLength);
    std::vector<uint8_t> entropyBinary(entropyBinaryString.begin(), entropyBinaryString.end());
    const auto generatedChecksum = entropyToMnemonic(entropyBinary);


    std::cout << generatedChecksum << std::endl;
    std::cout << finalChecksumBinaryString << std::endl;
    std::cout << finalChecksumBinaryString.size() << std::endl;
    return true;
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
