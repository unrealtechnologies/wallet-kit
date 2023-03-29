//
// Created by Ariel Saldana on 3/27/23.
//

#ifndef WALLET_KIT_LIB_EXTENDED_KEY_H
#define WALLET_KIT_LIB_EXTENDED_KEY_H

#include <iostream>
#include <vector>
#include <map>
#include <unordered_map>

// An extended key is defined as a construct of (k, c) k being the normal key, and c being the chaincode.
struct ExtendedKey {
    std::vector<uint8_t> key;
    std::vector<uint8_t> chainCode;
    std::unordered_map<size_t, ExtendedKey> children;

    size_t index;
//    size_t depth;


    std::string toBase58();
    std::vector<uint8_t> serialize();
    static std::vector<uint8_t> doubleSha256(std::vector<uint8_t> &data);
};

#endif //WALLET_KIT_LIB_EXTENDED_KEY_H
