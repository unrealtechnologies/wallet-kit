//
// Created by Ariel Saldana on 3/27/23.
//

#ifndef WALLET_KIT_LIB_BIP32_H
#define WALLET_KIT_LIB_BIP32_H

#include <iostream>
#include "wallet-kit/bip32/extended_key.h"
#include "wallet-kit/bip32/chain_node.h"

class Bip32 {
public:
    static std::unique_ptr<ChainNode> fromSeed(std::vector<uint8_t> &seed);
};

#endif //WALLET_KIT_LIB_BIP32_H
