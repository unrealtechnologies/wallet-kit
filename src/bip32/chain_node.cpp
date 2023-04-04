//
// Created by Ariel Saldana on 3/29/23.
//
#include <utility>
#include <wallet-kit/bip32/chain_node.h>
#include "wallet-kit/bip32.h"
#include <utils.h>

ChainNode::ChainNode(
        std::unique_ptr<ExtendedKey> privateKey,
        std::unique_ptr<ExtendedKey> publicKey) :
        privateKey(std::move(privateKey)),
        publicKey(std::move(publicKey)) {
}

std::unique_ptr<ExtendedKey> ChainNode::derivePrivateChildExtendedKey(bool withPrivateKey, uint32_t keyIndex, bool hardened) const {
    if (withPrivateKey) {
        auto fingerprintVec = std::get<1>(this->indexes.find(keyIndex)->second)->fingerPrint();
        uint32_t fingerprint =
                ((uint8_t) fingerprintVec[0] << 24) |
                ((uint8_t) fingerprintVec[1] << 16) |
                ((uint8_t) fingerprintVec[2] << 8) |
                ((uint8_t) fingerprintVec[3]);

        auto childIndex  = (hardened) ? keyIndex + 0x80000000 : keyIndex;
        auto pKey = *std::get<0>(this->indexes.find(childIndex)->second);
        return pKey.derivePrivateChildKey(childIndex, fingerprint, hardened);
    }

    return std::unique_ptr<ExtendedKey>();
}

std::tuple<ExtendedKey, ExtendedKey> ChainNode::findNode(const std::string &path) {
    if (path.empty()) {
        throw std::runtime_error("Path is empty");
    }

    if (path == "m") {
        auto prvKey = *std::get<0>(this->indexes.find(0)->second);
        auto pubKey = *std::get<1>(this->indexes.find(0)->second);
        return std::make_tuple(prvKey, pubKey);
    }

    auto pathArr = Bip32::parsePath(const_cast<std::string &>(path));

    if (pathArr.empty()) {
        throw std::runtime_error("Path arr is empty");
    }

    return this->search(this, pathArr);

//    if (pathArr.size() > 1) {
//        auto keyIndex = pathArr[0];
//        if (keyIndex >= 0x80000000) {
//
//        }
//    }
}

std::tuple<ExtendedKey, ExtendedKey> ChainNode::search(ChainNode *currentNode, const std::vector<uint32_t> &pathArr) {
    auto keyIndex = pathArr[0];
    if (pathArr.size() > 1) {

        if (keyIndex >= 0x80000000) {
            std::vector<uint32_t> subArr(pathArr.begin() + 1, pathArr.end());
            return this->search(currentNode->right.get(), subArr);
        }
    } else {
        auto prvKey = *std::get<0>(currentNode->indexes.find(keyIndex)->second);
        auto pubKey = *std::get<1>(currentNode->indexes.find(keyIndex)->second);
        return std::make_tuple(prvKey, pubKey);
    }
    return {};
}

std::tuple<ExtendedKey, ExtendedKey> ChainNode::derivePath(const std::string &path) {
    auto pathArr = Bip32::parsePath(const_cast<std::string &>(path));
    auto currentNode = this;
    uint32_t parentIndex = 0;
    for (auto index: pathArr) {
        auto prvKey = currentNode->derivePrivateChildExtendedKey(true, parentIndex, true);
        auto pubKey = prvKey->derivePublicChildKey();

        if (index >= 0x80000000) {
            currentNode->right = std::make_unique<ChainNode>(nullptr, nullptr);
            currentNode->right->indexes.insert(
                    std::make_pair(
                            index - 0x80000000,
                            std::make_tuple(std::move(prvKey), std::move(pubKey))
                    )
            );
            currentNode = currentNode->right.get();
        } else {
            currentNode->left = std::make_unique<ChainNode>(nullptr, nullptr);
            currentNode->left->indexes.insert(
                    std::make_pair(
                            index,
                            std::make_tuple(std::move(prvKey), std::move(pubKey))
                    )
            );
            currentNode = currentNode->left.get();
        }
        parentIndex = index;
    }

    auto childIndex = pathArr[pathArr.size() - 1] >= 0x80000000 ? pathArr[pathArr.size() - 1] - 0x80000000 : pathArr[pathArr.size() - 1];
    auto prvKey1 = *std::get<0>(currentNode->indexes.find(childIndex)->second);
    auto pubKey1 = *std::get<1>(currentNode->indexes.find(childIndex)->second);
    return std::make_tuple(prvKey1, pubKey1);
};

