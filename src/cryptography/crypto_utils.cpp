//
// Created by Ariel Saldana on 4/2/23.
//

#include <wallet-kit/cryptography/cryptography_context.h>
#include <wallet-kit/cryptography/crypto_utils.h>
#include <botan/sha2_32.h>
#include <botan/mac.h>
#include <botan/rmd160.h>
#include <secp256k1.h>
#include <botan/base58.h>

uint32_t WalletKitCryptoUtils::htobe32(uint32_t x) {
    union {
        uint32_t val;
        uint8_t bytes[4];
    } u;

    u.val = x;

    std::vector<uint8_t> vec(u.bytes, u.bytes + 4);
    std::reverse(vec.begin(), vec.end());

    std::copy(vec.begin(), vec.end(), u.bytes);

    return u.val;
}

std::vector<uint8_t> WalletKitCryptoUtils::uint32_to_big_endian(uint32_t num) {
    std::vector<uint8_t> vec(4);
    uint32_t be_num = htobe32(num); // Convert to big-endian
    std::memcpy(vec.data(), &be_num, sizeof(be_num)); // Copy to vector
    return vec;
}

std::vector<uint8_t> WalletKitCryptoUtils::doubleSha256(std::vector<uint8_t> &data) {
    // we don't need to manage the
    // lifecycle of the hash pointer,
    // commenting this out: std::unique_ptr<Botan::HashFunction> hash256(Botan::HashFunction::create("SHA-256"));
    // in favor of using Botan::SHA_256() directly.

    // compute the first sha256 hash
    auto hash256 = Botan::SHA_256();
    hash256.update(data.data(), data.size());
    auto firstSha256 = hash256.final();

    // clear for reuse
    hash256.clear();

    // compute the second sha256 hash
    hash256.update(firstSha256.data(), firstSha256.size());
    auto secondSha256 = hash256.final();

    return {secondSha256.begin(), secondSha256.end()};
}

std::vector<uint8_t> WalletKitCryptoUtils::hmac512(const std::vector<uint8_t> &msg, const std::vector<uint8_t> &key) {
    auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-512)");

    hmac->set_key(key);
    hmac->update(msg);
    auto hmacResult = hmac->final();

    // Copy the output to a new vector that uses the default allocator
    std::vector<uint8_t> result(hmacResult.begin(), hmacResult.end());
    return result;
}

std::vector<uint8_t> WalletKitCryptoUtils::sha256(const std::vector<uint8_t> &key) {
    auto hash256 = Botan::SHA_256();
    hash256.update(key.data(), key.size());
    auto sha256Digest = hash256.final();
    return {sha256Digest.begin(), sha256Digest.end()};
}

std::vector<uint8_t> WalletKitCryptoUtils::ripemd160(const std::vector<uint8_t> &key) {
    Botan::RIPEMD_160 ripemd160;
    auto output_data = ripemd160.process(key);
    std::vector<uint8_t> ripemd160vec(output_data.begin(), output_data.end());
    return {ripemd160vec.begin(), ripemd160vec.end()};
}

std::vector<uint8_t> WalletKitCryptoUtils::generatePublicKey(const std::vector<uint8_t> &key) {
    auto ctx = CryptoContext::getInstance().getSecp256k1Context();
    secp256k1_pubkey pubkey;

    std::unique_ptr<unsigned char[]> public_key33(new unsigned char[34]);
    memset(public_key33.get(), 0, 34);
    size_t pk_len = 34;

    /* Apparently there is a 2^-128 chance of
     * a secret key being invalid.
     * https://en.bitcoin.it/wiki/Private_key
     */
    /* Verify secret key is valid */
    if (!secp256k1_ec_seckey_verify(ctx, key.data())) {
        printf("Invalid secret key\n");
        throw std::runtime_error("Invalid secret key");
    }

    /* Create Public Key */
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, key.data())) {
        throw std::runtime_error("Failed to create public key");
    }

    /* Serialize Public Key */
    if (!secp256k1_ec_pubkey_serialize(ctx, public_key33.get(), &pk_len, &pubkey,
                                       SECP256K1_EC_COMPRESSED)) {
        throw std::runtime_error("Failed to serialize public key");
    }

    return {public_key33.get(), public_key33.get() + 33};
}

std::vector<uint8_t>
WalletKitCryptoUtils::generateprivateKey(const std::vector<uint8_t> &key, const std::vector<uint8_t> &tweak) {
    auto ctx = CryptoContext::getInstance().getSecp256k1Context();

    // make a copy to tweak
    auto privateKey(key);

    if (!secp256k1_ec_seckey_tweak_add(ctx, privateKey.data(), tweak.data())) {
        throw std::runtime_error("Failed to derive child private key");
    }

    return privateKey;
}

std::string WalletKitCryptoUtils::base58Encode(std::vector<uint8_t> &data) {
    return Botan::base58_encode(data);
}
