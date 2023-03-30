//
// Created by Ariel Saldana on 3/26/23.
//

#include <wallet-kit/bip32.h>
#include <botan/hex.h>
#include <botan/mac.h>
#include <secp256k1.h>
#include <utils.h>

static std::vector<uint8_t> compute_mac(const std::vector<uint8_t> &msg, const std::vector<uint8_t> &key) {
    auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-512)");

    hmac->set_key(key);
    hmac->update(msg);
    auto hmacResult = hmac->final();

    // Copy the output to a new vector that uses the default allocator
    std::vector<uint8_t> result(hmacResult.begin(), hmacResult.end());
    return result;
}

std::unique_ptr<ChainNode> Bip32::fromSeed(std::vector<uint8_t> &seed) {
    std::string keyString = "Bitcoin seed";
    std::vector<uint8_t> key(keyString.begin(), keyString.end());
    auto extendedKeyRaw = compute_mac(seed, key);
    size_t extendedKeyHalfwayIndex = extendedKeyRaw.size() / 2;

    // private key
    std::unique_ptr<ExtendedKey> extendedPrivateKey(new ExtendedKey());
    extendedPrivateKey->key = std::vector<uint8_t>(
            extendedKeyRaw.begin(),
            extendedKeyRaw.begin() + extendedKeyHalfwayIndex
    );
    extendedPrivateKey->chainCode = std::vector<uint8_t>(
            extendedKeyRaw.begin() + extendedKeyHalfwayIndex,
            extendedKeyRaw.end()
    );

    auto extendedPublicKey = derivePublicChildKey(*extendedPrivateKey);

    std::string path = "m";
    std::unique_ptr<ChainNode> chainNode(
            new ChainNode(path, std::move(extendedPrivateKey), std::move(extendedPublicKey))
    );


    return chainNode;
}

std::unique_ptr<ExtendedKey> Bip32::derivePublicChildKey(const ExtendedKey &key) {
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
    if (!secp256k1_ec_seckey_verify(ctx, key.key.data())) {
        printf("Invalid secret key\n");
        return nullptr;
    }

    /* Create Public Key */
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, key.key.data())) {
        printf("Failed to create public key\n");
        return nullptr;
    }

    /* Serialize Public Key */
    if (!secp256k1_ec_pubkey_serialize(ctx, public_key33.get(), &pk_len, &pubkey,
                                       SECP256K1_EC_COMPRESSED)) {
        printf("Failed to serialize public key\n");
        return nullptr;
    }


    std::unique_ptr<ExtendedKey> extendedKey(new ExtendedKey());
    extendedKey->key = std::vector<uint8_t>(public_key33.get(), public_key33.get() + 33);
    extendedKey->chainCode = key.chainCode;

    return extendedKey;
}

std::unique_ptr<ExtendedKey> Bip32::derivePrivateChildKey(const ExtendedKey& parentKey, uint32_t index, bool hardened) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    // Determine whether the child key is hardened or not
    uint32_t childIndex = index;
    if (hardened) {
        childIndex |= 0x80000000;
    }

    // Compute HMAC-SHA512 of parent key and child index
    std::vector<uint8_t> data(37);
    std::copy(parentKey.key.begin(), parentKey.key.end(), data.begin());
    data[33] = (childIndex >> 24) & 0xff;
    data[34] = (childIndex >> 16) & 0xff;
    data[35] = (childIndex >> 8) & 0xff;
    data[36] = childIndex & 0xff;

    auto I = compute_mac(data, parentKey.chainCode);

    // Split HMAC output into left (IL) and right (IR) 32-byte sequences
    std::vector<uint8_t> IL(I.begin(), I.begin() + 32);
    std::vector<uint8_t> IR(I.begin() + 32, I.end());

    // Derive child private key
    std::vector<uint8_t> childKey(32);
    if (!secp256k1_ec_seckey_tweak_add(ctx, childKey.data(), parentKey.key.data())) {
        printf("Failed to derive child private key\n");
    }

    // Compute child chain code
    std::vector<uint8_t> childChainCode = IR;

    // Construct child extended key
    std::unique_ptr<ExtendedKey> childExtendedKey(new ExtendedKey());
    childExtendedKey->key = childKey;
    childExtendedKey->chainCode = childChainCode;

    return childExtendedKey;
}

