//
// Created by Ariel Saldana on 3/26/23.
//

#include <wallet-kit/bip32.h>
#include <botan/hex.h>
#include <botan/mac.h>

static std::vector<uint8_t> compute_mac(const std::vector<uint8_t> &msg, const std::vector<uint8_t> &key) {
    auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-512)");

    hmac->set_key(key);
    hmac->update(msg);
    auto hmacResult = hmac->final();

    // Copy the output to a new vector that uses the default allocator
    std::vector<uint8_t> result(hmacResult.begin(), hmacResult.end());
    return result;
}

std::unique_ptr<ExtendedKey> Bip32::fromSeed(std::vector<uint8_t> &seed) {
    std::string keyString = "Bitcoin seed";
    std::vector<uint8_t> key(keyString.begin(), keyString.end());
    auto extendedKeyRaw = compute_mac(seed, key);
    size_t extendedKeyHalfwayIndex = extendedKeyRaw.size() / 2;

    std::unique_ptr<ExtendedKey> extendedKey(new ExtendedKey());
    extendedKey->key = std::vector<uint8_t>(
            extendedKeyRaw.begin(),
            extendedKeyRaw.begin() + extendedKeyHalfwayIndex
    );
    extendedKey->chainCode = std::vector<uint8_t>(
            extendedKeyRaw.begin() + extendedKeyHalfwayIndex,
            extendedKeyRaw.end()
    );
    return extendedKey;
}
