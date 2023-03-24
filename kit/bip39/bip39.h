//
// Created by Ariel Saldana on 3/24/23.
//

#ifndef WALLET_KIT_BIP39_H
#define WALLET_KIT_BIP39_H

#include <cstdint>
#include <iostream>

class Bip39 {

public:
    static std::string generateSeedWithEntropy(uint8_t*);
    static std::string getWordsFromEntropyBinary(const std::string&);
};

#endif //WALLET_KIT_BIP39_H
