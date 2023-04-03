//
// Created by Ariel Saldana on 3/30/23.
//

#ifndef WALLET_KIT_LIB_CHAIN_NODE_CONTEXT_H
#define WALLET_KIT_LIB_CHAIN_NODE_CONTEXT_H

#include <vector>

struct ChainNodeContext {
    uint8_t depth;
    uint32_t fingerprint;
    uint32_t childNumber;

    ChainNodeContext(uint8_t depth, uint32_t fingerprint, uint32_t childNumber);
};

#endif //WALLET_KIT_LIB_CHAIN_NODE_CONTEXT_H
