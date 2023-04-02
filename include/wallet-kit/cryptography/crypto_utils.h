//
// Created by Ariel Saldana on 4/2/23.
//

#ifndef WALLET_KIT_LIB_CRYPTO_UTILS_H
#define WALLET_KIT_LIB_CRYPTO_UTILS_H

#include <cstdint>
#include <vector>

namespace WalletKitCryptoUtils {
    uint32_t htobe32(uint32_t x);
    std::vector<uint8_t> uint32_to_big_endian(uint32_t num);
    std::vector<uint8_t> doubleSha256(std::vector<uint8_t> &data);
    std::vector<uint8_t> hmac512(const std::vector<uint8_t> &msg, const std::vector<uint8_t> &key);
    std::vector<uint8_t> sha256(const std::vector<uint8_t> &key);
    std::vector<uint8_t> ripemd160(const std::vector<uint8_t> &key);
    std::vector<uint8_t> generatePublicKey(const std::vector<uint8_t> &key);
    std::vector<uint8_t> generateprivateKey(const std::vector<uint8_t> &key, const std::vector<uint8_t> &tweak);
    std::string base58Encode(std::vector<uint8_t> & data);
}

#endif //WALLET_KIT_LIB_CRYPTO_UTILS_H
