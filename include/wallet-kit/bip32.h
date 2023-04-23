//
// Created by Ariel Saldana on 3/27/23.
//

#ifndef WALLET_KIT_LIB_BIP32_H
#define WALLET_KIT_LIB_BIP32_H

#include "extended_key.h"
#include "chain_node.h"

/**
 * @brief A class that provides functions for working with BIP32 hierarchical deterministic keys.
 */
class Bip32 {
public:
    /**
     * @brief Derives a chain of extended keys from a given seed.
     * @param seed A vector of bytes representing the seed.
     * @return A unique pointer to the root of the chain of extended keys.
     */
    static std::unique_ptr<ChainNode> fromSeed(std::vector<uint8_t> &seed);

    /**
     * @brief Parses a BIP32 path string into a vector of uint32_t values.
     * @param path A string representing the BIP32 path.
     * @return A vector of uint32_t values representing the parsed BIP32 path.
     */
    static std::vector<uint32_t> parsePath(std::string &path);
};

#endif //WALLET_KIT_LIB_BIP32_H
