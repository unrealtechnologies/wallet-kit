//
// Created by Ariel Saldana on 3/27/23.
//

#ifndef WALLET_KIT_LIB_EXTENDED_KEY_H
#define WALLET_KIT_LIB_EXTENDED_KEY_H

#include <iostream>
#include <vector>
#include "chain_node_context.h"

enum class KeyType {
    Public = 0x0488B21E,
    Private = 0x0488ADE4
};

// An extended key is defined as a construct of (k, c) k being the normal key, and c being the chaincode.
struct ExtendedKey {
    std::shared_ptr<ChainNodeContext> context;
    std::vector<uint8_t> key;
    std::vector<uint8_t> chainCode;

    std::string toBase58();

    std::vector<uint8_t> serialize();

    std::vector<uint8_t> fingerPrint() const;

    static std::vector<uint8_t> doubleSha256(std::vector<uint8_t> &data);

    std::unique_ptr<ExtendedKey> derivePublicChildKey() const;

    std::unique_ptr<ExtendedKey> derivePrivateChildKey(uint32_t index, uint32_t fingerprint);
};

#endif //WALLET_KIT_LIB_EXTENDED_KEY_H
