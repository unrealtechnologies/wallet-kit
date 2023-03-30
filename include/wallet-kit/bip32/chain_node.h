//
// Created by Ariel Saldana on 3/29/23.
//

#ifndef WALLET_KIT_LIB_CHAIN_NODE_H
#define WALLET_KIT_LIB_CHAIN_NODE_H

#include <iostream>
#include "extended_key.h"
#include <unordered_map>

struct ChainNode {
    std::string localPath;
    std::string fullPath;
    std::unique_ptr<ExtendedKey> privateKey;
    std::unique_ptr<ExtendedKey> publicKey;
    std::unordered_map<std::string, ChainNode> children;

    explicit ChainNode(std::string &path, std::unique_ptr<ExtendedKey> publicKey, std::unique_ptr<ExtendedKey> privateKey);

    void addChildren(const std::string& path, const ChainNode& child);
};

#endif //WALLET_KIT_LIB_CHAIN_NODE_H
