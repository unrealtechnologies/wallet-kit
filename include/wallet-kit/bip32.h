//
// Created by Ariel Saldana on 3/27/23.
//

#ifndef WALLET_KIT_LIB_BIP32_H
#define WALLET_KIT_LIB_BIP32_H

#include <iostream>
#include "wallet-kit/bip32/extended_key.h"

class Bip32 {
public:
    static std::unique_ptr<ExtendedKey> fromSeed(std::vector<uint8_t> &seed);

    static std::unique_ptr<ExtendedKey> derivePublicChildKey(ExtendedKey &key);

};

#endif //WALLET_KIT_LIB_BIP32_H
