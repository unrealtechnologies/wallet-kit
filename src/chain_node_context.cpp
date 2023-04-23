//
// Created by Ariel Saldana on 3/30/23.
//
#include "wallet-kit/chain_node_context.h"

ChainNodeContext::ChainNodeContext(
        uint8_t depth,
        uint32_t fingerprint,
        uint32_t childNumber) :
        depth(depth), fingerprint(fingerprint), childNumber(childNumber) {}

