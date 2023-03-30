//
// Created by Ariel Saldana on 3/29/23.
//
#include <utility>
#include <wallet-kit/bip32/chain_node.h>

//void ChainNode::addChildren(const std::string &path, const ChainNode &child) {
//    this->children.insert({path, child});
//}

//ChainNode::ChainNode(std::string &path, ExtendedKey &publicKey, ExtendedKey &privateKey) {
//    this->fullPath = path;
//    this->publicKey = publicKey;
//    this->privateKey = privateKey;
//}

ChainNode::ChainNode(
        std::string &path,
        std::unique_ptr<ExtendedKey> privateKey,
        std::unique_ptr<ExtendedKey> publicKey) : privateKey(std::move(privateKey)), publicKey(std::move(publicKey)) {
    this->localPath = path;
}

