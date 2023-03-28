//
// Created by Ariel Saldana on 3/27/23.
//

#ifndef WALLET_KIT_LIB_EXTENDED_KEY_H
#define WALLET_KIT_LIB_EXTENDED_KEY_H

#include <iostream>
#include <vector>

// An extended key is defined as a construct of (k, c) k being the normal key, and c being the chaincode.
struct ExtendedKey {
    std::vector<uint8_t> key;
    std::vector<uint8_t> chainCode;
    size_t index;

    std::string toBase58();
};

#endif //WALLET_KIT_LIB_EXTENDED_KEY_H
