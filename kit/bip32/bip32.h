//
// Created by Ariel Saldana on 3/25/23.
//

#ifndef WALLET_KIT_BIP32_H
#define WALLET_KIT_BIP32_H


#include <cstdint>
#include <iostream>

class bip32 {
public:
    static uint8_t *derivePrivateKey(uint8_t *);

    static uint8_t *derivePublicKey(uint8_t *privateKey);

    static uint8_t *derivePublicKeyCompressed(uint8_t *privateKey);

    void deriveMainKeyAndChainCode(uint8_t*bip39Seed, uint8_t *mainKey, uint8_t *chainCode);

    void childKeyDerivationPrivate(uint8_t *key, uint8_t *chainCode, size_t index, uint8_t *k, uint8_t *c);

    std::string sign(std::string key, std::string plain);
};

#endif //WALLET_KIT_BIP32_H
