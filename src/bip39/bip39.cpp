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
    if (entropy.size() <= 16 && entropy.size() >= 32 && entropy.size() % 4 != 0) {
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

std::vector<uint8_t> Bip39::mnemonicToSeed(std::string mnemonic) {
    // Define the password and salt to use
    std::string salt = "mnemonic";

    // Define the number of iterations to use
    const size_t iterations = 2048;

    // Define the output length of the key (in bytes)
    const size_t outputLength = 64;

    // Define the PRF to use (in this case, HMAC-SHA-512)
    std::unique_ptr<Botan::MessageAuthenticationCode> prf(Botan::MessageAuthenticationCode::create("HMAC(SHA-512)"));
    std::vector<uint8_t> password(mnemonic.begin(), mnemonic.end());
//    std::string s = " meow";
//    std::vector<std::uint8_t> bytes = getBytes(s);
//    std::copy (bytes.begin(), bytes.end(), std::back_inserter(password));
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
