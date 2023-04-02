//
// Created by Ariel Saldana on 3/29/23.
//

#ifndef WALLET_KIT_LIB_CHAIN_NODE_H
#define WALLET_KIT_LIB_CHAIN_NODE_H

#include <iostream>
#include <unordered_map>
#include <wallet-kit/bip32/extended_key.h>
#include <wallet-kit/bip32/chain_node_context.h>

struct ChainNode {
    std::string localPath;
    std::unique_ptr<ExtendedKey> privateKey;
    std::unique_ptr<ExtendedKey> publicKey;
    std::unordered_map<std::string, ChainNode> children;
    std::shared_ptr<ChainNodeContext> context;

    explicit ChainNode(std::string &path, std::unique_ptr<ExtendedKey> privateKey,
                       std::unique_ptr<ExtendedKey> publicKey);

    [[nodiscard]] std::unique_ptr<ExtendedKey> derivePublicChildKey(bool usingPrivateKey) const;

    [[nodiscard]] std::unique_ptr<ExtendedKey> derivePublicChildExtendedKey(bool withPrivateKey) const;

    [[nodiscard]] std::unique_ptr<ExtendedKey> derivePrivateChildExtendedKey(bool withPrivateKey) const;

//    void addChildren(const std::string &path, const ChainNode &child);
};

#endif //WALLET_KIT_LIB_CHAIN_NODE_H
