//
// Created by Ariel Saldana on 3/29/23.
//
#include <utility>
#include <wallet-kit/bip32/chain_node.h>
#include <secp256k1.h>

ChainNode::ChainNode(
        std::string &path,
        std::unique_ptr<ExtendedKey> privateKey,
        std::unique_ptr<ExtendedKey> publicKey) :
        localPath(path),
        privateKey(std::move(privateKey)),
        publicKey(std::move(publicKey)) {
    if (localPath != "m") {
        auto fingerprint = this->publicKey->fingerPrint();
        // Combine the first 4 bytes into a single 32-bit integer - this assumes our endian of the values is correct.
        uint32_t result =
                ((uint32_t) fingerprint[0] << 24) |
                ((uint32_t) fingerprint[1] << 16) |
                ((uint32_t) fingerprint[2] << 8) |
                ((uint32_t) fingerprint[3]);
        this->context->fingerprint = result;
        std::cout << "it's an m" << std::endl;
    } else {
//        std::cout << "not m" << std::endl;
    }
}

std::unique_ptr<ExtendedKey> ChainNode::derivePublicChildKey(bool usingPrivateKey) const {
    ExtendedKey key;
    if (usingPrivateKey) {
        key = *this->privateKey;
    } else {
        key = *this->publicKey;
    }

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pubkey;

    std::unique_ptr<unsigned char[]> public_key33(new unsigned char[34]);
    memset(public_key33.get(), 0, 34);
    size_t pk_len = 34;


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

std::unique_ptr<ExtendedKey> ChainNode::derivePublicChildExtendedKey(bool withPrivateKey) const {
    ExtendedKey key;
    if (withPrivateKey) {
        key = *this->privateKey;
        return key.derivePublicChildKey();
    } else {
        key = *this->publicKey;
    }

    return std::unique_ptr<ExtendedKey>();
}

std::unique_ptr<ExtendedKey> ChainNode::derivePrivateChildExtendedKey(bool withPrivateKey) const {
    if (withPrivateKey) {
        auto fingerprintVec = this->publicKey->fingerPrint();
        uint32_t fingerprint =
                ((uint32_t) fingerprintVec[0] << 24) |
                ((uint32_t) fingerprintVec[1] << 16) |
                ((uint32_t) fingerprintVec[2] << 8) |
                ((uint32_t) fingerprintVec[3]);

        return this->privateKey->derivePrivateChildKey(0, fingerprint);
    }

    return std::unique_ptr<ExtendedKey>();
};

