//
// Created by Ariel Saldana on 4/2/23.
//

#ifndef WALLET_KIT_LIB_CRYPTO_UTILS_H
#define WALLET_KIT_LIB_CRYPTO_UTILS_H

#include <vector>
#include <botan/base58.h>


namespace WalletKitCryptoUtils {
    uint32_t htobe32(uint32_t x);

    std::vector<uint8_t> uint32ToBigEndian(uint32_t num);

    std::vector<uint8_t> doubleSha256(std::vector<uint8_t> &data);

    std::vector<uint8_t> hmac512(const std::vector<uint8_t> &msg, const std::vector<uint8_t> &key);

    std::vector<uint8_t> sha256(const std::vector<uint8_t> &key);

    std::vector<uint8_t> ripemd160(const std::vector<uint8_t> &key);

    std::vector<uint8_t> generatePublicKey(const std::vector<uint8_t> &key, bool compressed = true);

    std::vector<uint8_t> generatePrivateKey(const std::vector<uint8_t> &key, const std::vector<uint8_t> &tweak);

    std::string base58Encode(std::vector<uint8_t> &data);

    Botan::secure_vector<uint8_t> keccak256(std::vector<uint8_t> &data);

    Botan::secure_vector<uint8_t> keccak256(const std::string &data);

    std::vector<uint8_t> generateEntropy(uint32_t length);
}

#endif //WALLET_KIT_LIB_CRYPTO_UTILS_H