//
// Created by Ariel Saldana on 3/29/23.
//
#include <utility>
#include <wallet-kit/bip32/chain_node.h>

ChainNode::ChainNode(
        std::unique_ptr<ExtendedKey> privateKey,
        std::unique_ptr<ExtendedKey> publicKey) :
        privateKey(std::move(privateKey)),
        publicKey(std::move(publicKey)) {
}

std::unique_ptr<ExtendedKey> ChainNode::derivePrivateChildExtendedKey(bool withPrivateKey) const {
    if (withPrivateKey) {
        auto fingerprintVec = this->publicKey->fingerPrint();
        uint32_t fingerprint =
                ((uint8_t) fingerprintVec[0] << 24) |
                ((uint8_t) fingerprintVec[1] << 16) |
                ((uint8_t) fingerprintVec[2] << 8) |
                ((uint8_t) fingerprintVec[3]);

        return this->privateKey->derivePrivateChildKey(0, fingerprint);
    }

    return std::unique_ptr<ExtendedKey>();
};

