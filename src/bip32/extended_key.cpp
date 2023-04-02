//
// Created by Ariel Saldana on 3/28/23.
//

#include "wallet-kit/bip32/extended_key.h"
#include "utils.h"
#include <vector>
#include <botan/base58.h>
#include <botan/rmd160.h>
#include <botan/sha2_32.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <botan/mac.h>


uint32_t htobe32(uint32_t x) {
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

std::vector<uint8_t> uint32_to_big_endian(const uint32_t num) {
    std::vector<uint8_t> vec(4);
    uint32_t be_num = htobe32(num); // Convert to big-endian
    std::memcpy(vec.data(), &be_num, sizeof(be_num)); // Copy to vector
    return vec;
}

std::string ExtendedKey::toBase58() {

    if (this->context == nullptr) {
        throw std::runtime_error("ExtendedKey context is null");
    }

    auto serializedStructure = this->serialize();
    auto base58EncodedString = Botan::base58_encode(serializedStructure);
    return base58EncodedString;
}

std::vector<uint8_t> ExtendedKey::serialize() {
    std::vector<uint8_t> structure;
    structure.reserve(78);

    const std::vector<uint8_t> privateVersion = {0x04, 0x88, 0xAD, 0xE4};   // 4 bytes version
    const std::vector<uint8_t> publicVersion = {0x04, 0x88, 0xB2, 0x1E};    // 4 bytes version

    if (this->key.size() == 32) {
        structure.insert(structure.end(), privateVersion.begin(), privateVersion.end());
    } else {
        structure.insert(structure.end(), publicVersion.begin(), publicVersion.end());
    }

    structure.insert(structure.end(), reinterpret_cast<const uint8_t *>(&this->context->depth),
                     reinterpret_cast<const uint8_t *>(&this->context->depth) + sizeof(this->context->depth));

    std::vector<uint8_t> fingerprintBigEndianOrder = {g
            static_cast<unsigned char>((this->context->fingerprint >> 24) & 0xff),
            static_cast<unsigned char>((this->context->fingerprint >> 16) & 0xff),
            static_cast<unsigned char>((this->context->fingerprint >> 8) & 0xff),
            static_cast<unsigned char>(this->context->fingerprint & 0xff)
    };
    structure.insert(structure.end(), fingerprintBigEndianOrder.begin(), fingerprintBigEndianOrder.end());

    std::vector<uint8_t> childNumberBigEndianOrder = {
            static_cast<unsigned char>((this->context->childNumber >> 24) & 0xff),
            static_cast<unsigned char>((this->context->childNumber >> 16) & 0xff),
            static_cast<unsigned char>((this->context->childNumber >> 8) & 0xff),
            static_cast<unsigned char>(this->context->childNumber & 0xff)
    };
    structure.insert(structure.end(), childNumberBigEndianOrder.begin(), childNumberBigEndianOrder.end());

    structure.insert(structure.end(), this->chainCode.begin(), this->chainCode.end());

    if (this->key.size() == 32) {
        structure.push_back(0x00);
    }
    structure.insert(structure.end(), this->key.begin(), this->key.end());
    auto str = walletKitUtils::to_hex(structure, 78);

    // take the first 4 bytes of the double sha256 of the 78 byte structure above and append it to the structure.
    std::vector<uint8_t> doubleSha256Checksum = ExtendedKey::doubleSha256(structure);
    structure.insert(structure.end(), doubleSha256Checksum.begin(), doubleSha256Checksum.begin() + 4);

    return structure;
}

std::vector<uint8_t> ExtendedKey::doubleSha256(std::vector<uint8_t> &data) {
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

std::vector<uint8_t> ExtendedKey::fingerPrint() {
    // Compute the first SHA256 hash
    auto hash256 = Botan::SHA_256();
    hash256.update(this->key.data(), this->key.size());
    auto firstSha256 = hash256.final();

    Botan::RIPEMD_160 ripemd160;
    auto output_data = ripemd160.process(firstSha256);
    std::vector<uint8_t> ripemd160vec(output_data.begin(), output_data.end());

    return {ripemd160vec.begin(), ripemd160vec.end()};
}

std::unique_ptr<ExtendedKey> ExtendedKey::derivePublicChildKey() {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pubkey;

    std::unique_ptr<unsigned char[]> public_key33(new unsigned char[34]);
    memset(public_key33.get(), 0, 34);
    size_t pk_len = 34;

    /* Apparently there is a 2^-128 chance of
     * a secret key being invalid.
     * https://en.bitcoin.it/wiki/Private_key
     */

    /* Verify secret key is valid */
    if (!secp256k1_ec_seckey_verify(ctx, this->key.data())) {
        printf("Invalid secret key\n");
        return nullptr;
    }

    /* Create Public Key */
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, this->key.data())) {
        printf("Failed to create public key\n");
        return nullptr;
    }

    /* Serialize Public Key */
    if (!secp256k1_ec_pubkey_serialize(ctx, public_key33.get(), &pk_len, &pubkey,
                                       SECP256K1_EC_COMPRESSED)) {
        printf("Failed to serialize public key\n");
        return nullptr;
    }


    std::unique_ptr<ExtendedKey> publicExtendedKey(new ExtendedKey());
    publicExtendedKey->key = std::vector<uint8_t>(public_key33.get(), public_key33.get() + 33);
    publicExtendedKey->chainCode = this->chainCode;
    publicExtendedKey->context = this->context;

    return publicExtendedKey;
}

static std::vector<uint8_t> compute_mac(const std::vector<uint8_t> &msg, const std::vector<uint8_t> &key) {
    auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-512)");

    hmac->set_key(key);
    hmac->update(msg);
    auto hmacResult = hmac->final();

    // Copy the output to a new vector that uses the default allocator
    std::vector<uint8_t> result(hmacResult.begin(), hmacResult.end());
    return result;
}

std::unique_ptr<ExtendedKey> ExtendedKey::derivePrivateChildKey(uint32_t index, uint32_t fingerprint) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    // Determine whether the child key is hardened or not
    uint32_t childIndex = index;

    bool hardened = true;
    if (hardened) {
        childIndex |= 0x80000000;
    }

    /*
     * Check whether i ≥ 231 (whether the child is a hardened key).
     * If so (hardened child): let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i)).
     * (Note: The 0x00 pads the private key to make it 33 bytes long.)
     */

    // Compute HMAC-SHA512 of parent key and child index
    std::vector<uint8_t> data(37);
    data[0] = 0x00;
    std::copy(this->key.begin(), this->key.end(), data.begin() + 1);
    data[33] = (childIndex >> 24) & 0xff;
    data[34] = (childIndex >> 16) & 0xff;
    data[35] = (childIndex >> 8) & 0xff;
    data[36] = childIndex & 0xff;

    auto I = compute_mac(data, this->chainCode);

    // Split HMAC output into left (IL) and right (IR) 32-byte sequences
    // (IL) is used as the tweak value, (IR) is used as the child chain code
    std::vector<uint8_t> IL(I.begin(), I.begin() + 32);
    std::vector<uint8_t> IR(I.begin() + 32, I.end());

    // Derive child private key
    std::vector<uint8_t> childKey(this->key);

//    if (!secp256k1_ec_seckey_tweak_add(ctx, IL.data(), parentKey.key.data())) {
    if (!secp256k1_ec_seckey_tweak_add(ctx, childKey.data(), IL.data())) {
        throw std::runtime_error("Failed to derive child private key");
    }

    // Compute child chain code
    const std::vector<uint8_t> &childChainCode = IR;

    auto privateKeyContext = std::make_shared<ChainNodeContext>(
            ++this->context->depth,
            fingerprint,
            childIndex
    );

    // Construct child extended key
    std::unique_ptr<ExtendedKey> childExtendedKey(new ExtendedKey());
    childExtendedKey->key = childKey;
    childExtendedKey->chainCode = childChainCode;
    childExtendedKey->context = privateKeyContext;

    return childExtendedKey;
}

