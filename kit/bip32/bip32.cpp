//
// Created by Ariel Saldana on 3/25/23.
//

#include "bip32.h"
#include "../bip39/to_hex.h"
#include <iostream>
#include <secp256k1.h>
#include <hmac_sha256.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <cstring>
#include <openssl/evp.h>

void bip32::deriveMainKeyAndChainCode(uint8_t *bip39Seed, uint8_t *mainKey, uint8_t *chainCode) {
    const char* key = "Bitcoin seed";
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;

    std::cout << "bip39seed2: " << to_hex(bip39Seed, 64) << std::endl;

    HMAC(EVP_sha512(), key, strlen(key), (const uint8_t*) bip39Seed, 64, digest, &digest_len);


    // Copy the first half into the first array
    std::copy(digest, digest + (digest_len / 2), mainKey);

    // Copy the second half into the second array
    std::copy(digest + (digest_len / 2), digest + digest_len, chainCode);

    std::cout << "HMAC-SHA512 digest: ";
    for (unsigned int i = 0; i < digest_len; ++i) {
        printf("%02x", digest[i]);
    }
    std::cout << std::endl;
}


uint8_t *bip32::derivePrivateKey(uint8_t *privKey) {
//    unsigned char msg_hash[32] = {
//            0x31, 0x5F, 0x5B, 0xDB, 0x76, 0xD0, 0x78, 0xC4,
//            0x3B, 0x8A, 0xC0, 0x06, 0x4E, 0x4A, 0x01, 0x64,
//            0x61, 0x2B, 0x1F, 0xCE, 0x77, 0xC8, 0x69, 0x34,
//            0x5B, 0xFC, 0x94, 0xC7, 0x58, 0x94, 0xED, 0xD3,
//    };
//    unsigned char seckey[32];
//    unsigned char randomize[32];
//    unsigned char compressed_pubkey[33];
//    unsigned char serialized_signature[64];
//    size_t len;
//    int is_signature_valid, is_signature_valid2;
//    int return_val;
//    secp256k1_pubkey pubkey;
//    secp256k1_ecdsa_signature sig;
//    /* Before we can call actual API functions, we need to create a "context". */
//    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
//    if (!fill_random(randomize, sizeof(randomize))) {
//        printf("Failed to generate randomness\n");
//        return 1;
//    }
//    /* Randomizing the context is recommended to protect against side-channel
//     * leakage See `secp256k1_context_randomize` in secp256k1.h for more
//     * information about it. This should never fail. */
//    return_val = secp256k1_context_randomize(ctx, randomize);
//    assert(return_val);
//
//    /*** Key Generation ***/
//
//    /* If the secret key is zero or out of range (bigger than secp256k1's
//     * order), we try to sample a new key. Note that the probability of this
//     * happening is negligible. */
//    while (1) {
//        if (!fill_random(seckey, sizeof(seckey))) {
//            printf("Failed to generate randomness\n");
//            return 1;
//        }
//        if (secp256k1_ec_seckey_verify(ctx, seckey)) {
//            break;
//        }
//    }
//
//    /* Public key creation using a valid context with a verified secret key should never fail */
//    return_val = secp256k1_ec_pubkey_create(ctx, &pubkey, seckey);
//    assert(return_val);
//
//    /* Serialize the pubkey in a compressed form(33 bytes). Should always return 1. */
//    len = sizeof(compressed_pubkey);
//    return_val = secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED);
//    assert(return_val);
//    /* Should be the same size as the size of the output, because we passed a 33 byte array. */
//    assert(len == sizeof(compressed_pubkey));
//
//    /*** Signing ***/
//
//    /* Generate an ECDSA signature `noncefp` and `ndata` allows you to pass a
//     * custom nonce function, passing `NULL` will use the RFC-6979 safe default.
//     * Signing with a valid context, verified secret key
//     * and the default nonce function should never fail. */
//    return_val = secp256k1_ecdsa_sign(ctx, &sig, msg_hash, seckey, NULL, NULL);
//    assert(return_val);
//
//    /* Serialize the signature in a compact form. Should always return 1
//     * according to the documentation in secp256k1.h. */
//    return_val = secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_signature, &sig);
//    assert(return_val);
//
//
//    /*** Verification ***/
//
//    /* Deserialize the signature. This will return 0 if the signature can't be parsed correctly. */
//    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, serialized_signature)) {
//        printf("Failed parsing the signature\n");
//        return 1;
//    }
//
//    /* Deserialize the public key. This will return 0 if the public key can't be parsed correctly. */
//    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, compressed_pubkey, sizeof(compressed_pubkey))) {
//        printf("Failed parsing the public key\n");
//        return 1;
//    }
//
//    /* Verify a signature. This will return 1 if it's valid and 0 if it's not. */
//    is_signature_valid = secp256k1_ecdsa_verify(ctx, &sig, msg_hash, &pubkey);
//
//    printf("Is the signature valid? %s\n", is_signature_valid ? "true" : "false");
//    printf("Secret Key: ");
//    print_hex(seckey, sizeof(seckey));
//    printf("Public Key: ");
//    print_hex(compressed_pubkey, sizeof(compressed_pubkey));
//    printf("Signature: ");
//    print_hex(serialized_signature, sizeof(serialized_signature));
//
//    /* This will clear everything from the context and free the memory */
//    secp256k1_context_destroy(ctx);
//
//    /* Bonus example: if all we need is signature verification (and no key
//       generation or signing), we don't need to use a context created via
//       secp256k1_context_create(). We can simply use the static (i.e., global)
//       context secp256k1_context_static. See its description in
//       include/secp256k1.h for details. */
//    is_signature_valid2 = secp256k1_ecdsa_verify(secp256k1_context_static,
//                                                 &sig, msg_hash, &pubkey);
//    assert(is_signature_valid2 == is_signature_valid);
//
//    /* It's best practice to try to clear secrets from memory after using them.
//     * This is done because some bugs can allow an attacker to leak memory, for
//     * example through "out of bounds" array access (see Heartbleed), Or the OS
//     * swapping them to disk. Hence, we overwrite the secret key buffer with zeros.
//     *
//     * Here we are preventing these writes from being optimized out, as any good compiler
//     * will remove any writes that aren't used. */
//    secure_erase(seckey, sizeof(seckey));

    return nullptr;
}

uint8_t *bip32::derivePublicKey(uint8_t *privateKey) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pubkey;

    // unsigned char public_key64[65];
    unsigned char *public_key64 = (unsigned char *) malloc(65);
    memset(public_key64, 0, 65);
    size_t pk_len = 65;

    /* Apparently there is a 2^-128 chance of
     * a secret key being invalid.
     * https://en.bitcoin.it/wiki/Private_key
     */

    /* Verify secret key is valid */
    if (!secp256k1_ec_seckey_verify(ctx, privateKey)) {
        printf("Invalid secret key\n");
    }

    /* Create Public Key */
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privateKey)) {
        printf("Failed to create public key\n");
    }

    /* Serialize Public Key */
    secp256k1_ec_pubkey_serialize(ctx, public_key64, &pk_len, &pubkey,
                                  SECP256K1_EC_UNCOMPRESSED);

//    printf("Long Public Key C++ : ");
//    for(int j=0; j<65; j++) {
//        printf("%02X", public_key64[j]);
//    }
//    printf("\n\n");

    return public_key64;
}

uint8_t *bip32::derivePublicKeyCompressed(uint8_t *privateKey) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pubkey;
    unsigned char *public_key32 = (unsigned char *) malloc(33);
    memset(public_key32, 0, 33);
    size_t pk_len = 33;

    /* Apparently there is a 2^-128 chance of
     * a secret key being invalid.
     * https://en.bitcoin.it/wiki/Private_key
     */

    /* Verify secret key is valid */
    if (!secp256k1_ec_seckey_verify(ctx, privateKey)) {
        printf("Invalid secret key\n");
    }


    /* Create Public Key */
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privateKey)) {
        printf("Failed to create public key\n");
    }

    /* Serialize Public Key */
    secp256k1_ec_pubkey_serialize(ctx, public_key32, &pk_len, &pubkey,
                                  SECP256K1_EC_COMPRESSED);

//    printf("Long Public Key C++ : ");
//    for(int j=0; j<65; j++) {
//        printf("%02X", public_key32[j]);
//    }
//    printf("\n\n");

    return public_key32;
}

uint8_t from_big_endian(const uint8_t* data)
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           ((uint32_t)data[3]);
}

void to_big_endian(const uint32_t value, uint8_t* output)
{
    output[0] = (uint8_t)(value >> 24);
    output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8);
    output[3] = (uint8_t)value;
}

void bip32::childKeyDerivationPrivate(uint8_t *key, uint8_t *chainCode, size_t index, uint8_t *k, uint8_t *c) {

    // hardened key
    if (index < 2147483648) {
        const char* key = "Bitcoin seed";
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len;

        //If so (hardened child): let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i)).
        uint8_t* hmacKey = (uint8_t*)std::malloc(32 + 1);
        std::memcpy(&hmacKey[1], key, 32);
        hmacKey[0] = 0x00;

        HMAC(EVP_sha512(), chainCode, 32, hmacKey, 33, digest, &digest_len);

        // Copy the first half into the first array
        std::copy(digest, digest + (digest_len / 2), k);

        // Copy the second half into the second array
        std::copy(digest + (digest_len / 2), digest + digest_len, c);
    }
}


