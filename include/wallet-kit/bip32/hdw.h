//
// Created by Ariel Saldana on 3/28/23.
//

#ifndef WALLET_KIT_LIB_HDW_H
#define WALLET_KIT_LIB_HDW_H

#include "extended_key.h"

// Hierarchical Deterministic Wallets
class HDW {

    explicit HDW(std::shared_ptr<ExtendedKey> &extendedKey);

    ExtendedKey root;

public:
    ExtendedKey getRoot() {
        return root;
    }

    void derivePath(std::string);
};

#endif //WALLET_KIT_LIB_HDW_H
