//
// Created by Ariel Saldana on 3/26/23.
//

#include <wallet-kit/bip32.h>
#include <botan/hex.h>
#include <botan/mac.h>
#include <secp256k1.h>
#include <utils.h>

#include <memory>

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
    uint32_t extendedKeyHalfwayIndex = extendedKeyRaw.size() / 2;

    // default chain node context
    std::shared_ptr<ChainNodeContext> context(new ChainNodeContext(0, 0, 0));

    // private key
    std::unique_ptr<ExtendedKey> extendedPrivateKey(new ExtendedKey());
    extendedPrivateKey->context = context;
    extendedPrivateKey->key = std::vector<uint8_t>(
            extendedKeyRaw.begin(),
            extendedKeyRaw.begin() + extendedKeyHalfwayIndex
    );
    extendedPrivateKey->chainCode = std::vector<uint8_t>(
            extendedKeyRaw.begin() + extendedKeyHalfwayIndex,
            extendedKeyRaw.end()
    );

//    auto extendedPublicKey = derivePublicChildKey(*extendedPrivateKey); todo remove this
    auto extendedPublicKey = extendedPrivateKey->derivePublicChildKey();

    std::string path = "m";
    std::unique_ptr<ChainNode> chainNode(
            new ChainNode(
                    path,
                    std::move(extendedPrivateKey),
                    std::move(extendedPublicKey)
            )
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
    extendedKey->context = key.context;

    return extendedKey;
}

std::unique_ptr<ExtendedKey> Bip32::derivePrivateChildKey(const ExtendedKey &parentKey, uint32_t index, bool hardened) {

//    auto fingerprint = parentKey.fingerPrint()

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
//    std::vector<uint8_t> childKey(32);
    std::vector<uint8_t> childKey(parentKey.key);

//    if (!secp256k1_ec_seckey_tweak_add(ctx, IL.data(), parentKey.key.data())) {
    if (!secp256k1_ec_seckey_tweak_add(ctx, childKey.data(), IL.data())) {
        throw std::runtime_error("Failed to derive child private key");
    }

    // Compute child chain code
    const std::vector<uint8_t> &childChainCode = IR;

    auto context = std::make_shared<ChainNodeContext>(
            ++parentKey.context->depth,
            0,
            0
    );

    // Construct child extended key
    std::unique_ptr<ExtendedKey> childExtendedKey(new ExtendedKey());
    childExtendedKey->key = childKey;
    childExtendedKey->chainCode = childChainCode;
    childExtendedKey->context = context;

    return childExtendedKey;
}

//std::unique_ptr<ExtendedKey> Bip32::derivePrivateChildKey(ExtendedKey &parentKey, uint32_t index) {
//    uint32_t HARDENED_OFFSET = 0x80000000; //2147483648
//    if (index < HARDENED_OFFSET) {
//        throw std::invalid_argument("Invalid index: index must be a hardened index.");
//    }
//    if (parentKey.key.size() != 32) {
//        throw std::invalid_argument("Invalid parent key: key must be a 32-byte private key.");
//    }
//
//    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
//    secp256k1_pubkey pubkey;
//    secp256k1_ecdsa_signature signature;
//
//    // Compute the child key index
//    uint32_t childIndex = index | HARDENED_OFFSET;
//
//    // Serialize the parent public key
//    unsigned char parentPublicKey[33];
//    size_t parentPublicKeySize = sizeof(parentPublicKey);
//    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, parentKey.key.data()) ||
//        !secp256k1_ec_pubkey_serialize(ctx, parentPublicKey, &parentPublicKeySize, &pubkey, SECP256K1_EC_COMPRESSED)) {
//        throw std::runtime_error("Failed to serialize parent public key");
//    }
//
//    // Create the message for computing the HMAC
//    std::vector<uint8_t> message(37);
//    std::memcpy(message.data(), parentPublicKey, parentPublicKeySize);
////    Utils::pack32BE(childIndex, message.data() + parentPublicKeySize);
//
//    // Compute the HMAC of the message using the parent chain code as the key
//    auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-512)");
//    hmac->set_key(parentKey.chainCode);
//    hmac->update(message);
//    std::vector<uint8_t> hmacResult = hmac->final();
//
//    // Split the HMAC into two 32-byte parts
//    std::vector<uint8_t> hmacLeft(hmacResult.begin(), hmacResult.begin() + 32);
//    std::vector<uint8_t> hmacRight(hmacResult.begin() + 32, hmacResult.end());
//
//    // Compute the child private key by adding the left HMAC to the parent private key
//    std::vector<uint8_t> childKey(32);
//    if (!secp256k1_ec_seckey_tweak_add(ctx, childKey.data(), parentKey.key.data())) {
//        throw std::runtime_error("Failed to derive child private key");
//    }
//
//    // Compute the chain code by using the right HMAC
//    std::unique_ptr<ExtendedKey> childKeyPtr(new ExtendedKey());
//    childKeyPtr->key = childKey;
//    childKeyPtr->chainCode = hmacRight;
//
//    secp256k1_context_destroy(ctx);
//
//    return childKeyPtr;
//}


