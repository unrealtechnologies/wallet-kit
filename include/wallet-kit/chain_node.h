//
// Created by Ariel Saldana on 3/29/23.
//

#ifndef WALLET_KIT_LIB_CHAIN_NODE_H
#define WALLET_KIT_LIB_CHAIN_NODE_H

#include <iostream>
#include <unordered_map>
#include "extended_key.h"
#include "chain_node_context.h"
#include <memory>

struct ChainNode {
    std::unordered_map<uint32_t, std::tuple<std::unique_ptr<ExtendedKey>, std::unique_ptr<ExtendedKey>>> indexes;
    std::shared_ptr<ChainNodeContext> context;
    std::unique_ptr<ChainNode> left; // normal keys
    std::unique_ptr<ChainNode> right; // hardened keys

    explicit ChainNode();

    [[nodiscard]] std::unique_ptr<ExtendedKey> derivePrivateChildExtendedKey(
            uint32_t parentKeyIndex,
            uint32_t childKeyIndex,
            bool hardened
    ) const;

    [[nodiscard]] std::tuple<ExtendedKey, ExtendedKey> findNode(
            const std::string &path
    );

    [[nodiscard]] std::tuple<ExtendedKey, ExtendedKey> search(
            ChainNode *currentNode,
            const std::vector<uint32_t> &pathArr
    );

    [[nodiscard]] std::tuple<ExtendedKey, ExtendedKey> derivePath(const std::string &path);

private:
    static void insertIndexIntoNode(ChainNode* node, uint32_t index, std::unique_ptr<ExtendedKey> prvKey, std::unique_ptr<ExtendedKey> pubKey);
};

#endif //WALLET_KIT_LIB_CHAIN_NODE_H
