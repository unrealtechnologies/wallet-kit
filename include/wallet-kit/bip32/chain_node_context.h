//
// Created by Ariel Saldana on 3/30/23.
//

#ifndef WALLET_KIT_LIB_CHAIN_NODE_CONTEXT_H
#define WALLET_KIT_LIB_CHAIN_NODE_CONTEXT_H

#include <iostream>
#include <vector>å

struct ChainNodeContext {
    uint8_t depth;
    uint32_t fingerprint;
    uint32_t childNumber;
//    std::vector<uint8_t> rawFingerPrint;


    ChainNodeContext(uint8_t depth, uint32_t fingerprint, uint32_t childNumber);
};

#endif //WALLET_KIT_LIB_CHAIN_NODE_CONTEXT_H
