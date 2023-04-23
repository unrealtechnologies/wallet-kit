//
// Created by Ariel Saldana on 3/27/23.
//

#ifndef WALLET_KIT_LIB_BIP32_H
#define WALLET_KIT_LIB_BIP32_H

#include "extended_key.h"
#include "chain_node.h"

class Bip32 {
public:
    static std::unique_ptr<ChainNode> fromSeed(std::vector<uint8_t> &seed);
    static std::vector<uint32_t> parsePath(std::string &path);
};

#endif //WALLET_KIT_LIB_BIP32_H
