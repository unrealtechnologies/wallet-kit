//
// Created by Ariel Saldana on 3/24/23.
//

#ifndef WALLET_KIT_BIP39_H
#define WALLET_KIT_BIP39_H

#include <cstdint>
#include <iostream>

class Bip39 {
private:
    static void generateBip39SeedFromMnemonic(const std::string&, uint8_t (&bip39Seed)[64]);
public:
    static std::string generateSeedWithEntropy(uint8_t*, size_t);
    static std::string getWordsStringFromEntropyBits(const std::string&);
};

#endif //WALLET_KIT_BIP39_H
