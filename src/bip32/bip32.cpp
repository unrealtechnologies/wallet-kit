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

std::unique_ptr<ExtendedKey> Bip32::derivePublicChildKey(ExtendedKey &key) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pubkey;

    // unsigned char public_key64[65];
    unsigned char *public_key33 = (unsigned char *) malloc(34);
    memset(public_key33, 0, 34);
    size_t pk_len = 34;

    /* Apparently there is a 2^-128 chance of
     * a secret key being invalid.
     * https://en.bitcoin.it/wiki/Private_key
     */

    /* Verify secret key is valid */
    if (!secp256k1_ec_seckey_verify(ctx, key.key.data())) {
        printf("Invalid secret key\n");
    }

    /* Create Public Key */
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, key.key.data())) {
        printf("Failed to create public key\n");
    }

    /* Serialize Public Key */
    secp256k1_ec_pubkey_serialize(ctx, public_key33, &pk_len, &pubkey,
                                  SECP256K1_EC_COMPRESSED);

    std::unique_ptr<ExtendedKey> extendedKey(new ExtendedKey());
    extendedKey->key = std::vector<uint8_t>(public_key33, public_key33 + 33);
    extendedKey->chainCode = key.chainCode;

    return extendedKey;
}
