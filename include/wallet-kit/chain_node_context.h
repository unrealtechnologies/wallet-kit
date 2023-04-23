//
// Created by Ariel Saldana on 3/30/23.
//

#ifndef WALLET_KIT_LIB_CHAIN_NODE_CONTEXT_H
#define WALLET_KIT_LIB_CHAIN_NODE_CONTEXT_H

#include <cstdint>
/**
 * @brief The ChainNodeContext struct represents context information for a node in a chain.
 */
struct ChainNodeContext {
    uint8_t depth;
    uint32_t fingerprint;
    uint32_t childNumber;

    /**
     * @brief Constructs a ChainNodeContext object with the specified parameters.
     * @param depth The depth of the node in the chain.
     * @param fingerprint The fingerprint of the node.
     * @param childNumber The child number of the node.
     */
    ChainNodeContext(uint8_t depth, uint32_t fingerprint, uint32_t childNumber);
};

#endif //WALLET_KIT_LIB_CHAIN_NODE_CONTEXT_H
