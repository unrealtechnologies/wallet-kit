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
//    std::tuple<std::unique_ptr<PublicExtendedKey>, std::unique_ptr<PrivateExtendedKey>> keyPair;
    std::unique_ptr<ExtendedKey> privateKey;
    std::unique_ptr<ExtendedKey> publicKey;
    std::unordered_map<uint32_t, std::tuple<std::unique_ptr<ExtendedKey>, std::unique_ptr<ExtendedKey>>> indexes;
    std::shared_ptr<ChainNodeContext> context;
    std::unique_ptr<ChainNode> left; // normal keys
    std::unique_ptr<ChainNode> right; // hardened keys

    explicit ChainNode(std::unique_ptr<ExtendedKey> privateKey, std::unique_ptr<ExtendedKey> publicKey);

    [[nodiscard]] std::unique_ptr<ExtendedKey> derivePrivateChildExtendedKey(
            bool withPrivateKey,
            uint32_t keyIndex) const;

    [[nodiscard]] std::tuple<ExtendedKey, ExtendedKey> findNode(
            const std::string &path
    );

    [[nodiscard]] std::tuple<ExtendedKey, ExtendedKey> search(
            ChainNode *currentNode,
            const std::vector<uint32_t>& pathArr
    );

    [[nodiscard]] std::tuple<ExtendedKey, ExtendedKey> derivePath(const std::string &path);



    //    [[nodiscard]] std::unique_ptr<ExtendedKey> derivePublicChildKey(bool usingPrivateKey) const;
//    [[nodiscard]] std::unique_ptr<ExtendedKey> derivePublicChildExtendedKey(bool withPrivateKey) const;
//    void addChildren(const std::string &path, const ChainNode &child);
};

#endif //WALLET_KIT_LIB_CHAIN_NODE_H
