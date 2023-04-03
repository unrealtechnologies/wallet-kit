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
    if (entropy.size() != 16 && entropy.size() != 32) {
        throw std::runtime_error("Key size should be 128 or 256 bits");
    }

    auto checksum = getEntropyChecksum(entropy);

    std::vector<uint8_t> fullEntropy(entropy.begin(), entropy.end());
    fullEntropy.insert(fullEntropy.end(), checksum.begin(), checksum.end());

    auto fullEntropyBinaryString = WalletKitUtils::vecToBinaryString(fullEntropy);

    if (fullEntropyBinaryString.length() % 11 != 0) {
        throw std::runtime_error("Error with entropy string + checksum");
    }

    return fullEntropyBitsToMnemonicWords(fullEntropyBinaryString);
}

std::vector<uint8_t> Bip39::mnemonicToSeed(std::string mnemonic) {
    // Define the password and salt to use
    std::string salt = "mnemonic";

    // Define the number of iterations to use
    const size_t iterations = 2048;

    // Define the output length of the key (in bytes)
    const size_t output_length = 64;

    // Define the PRF to use (in this case, HMAC-SHA-512)
    std::unique_ptr<Botan::MessageAuthenticationCode> prf(Botan::MessageAuthenticationCode::create("HMAC(SHA-512)"));
    std::vector<uint8_t> password(mnemonic.begin(), mnemonic.end());
    prf->set_key(password);

    // make the output buffer twice the length of the output.
    uint8_t out[output_length * 2];

    const auto *saltUint8 = reinterpret_cast<const uint8_t *>(salt.c_str());
    Botan::pbkdf2(*prf,
                  out, output_length,
                  saltUint8, salt.length(),
                  iterations
    );

    std::vector<uint8_t> seed(out, out + output_length);
    return seed;
}


std::string Bip39::fullEntropyBitsToMnemonicWords(const std::string &fullEntropyString) {
    auto wordsBinaryArr = WalletKitUtils::split(fullEntropyString, 11);

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
