//
// Created by Ariel Saldana on 3/25/23.
//

#ifndef WALLET_KIT_BIP32_H
#define WALLET_KIT_BIP32_H


#include <cstdint>

class bip32 {
public:
    static uint8_t* derivePrivateKey();
};


#endif //WALLET_KIT_BIP32_H
