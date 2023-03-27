//
// Created by Ariel Saldana on 3/26/23.
//

#ifndef WALLET_KIT_LIB_BIP39_H
#define WALLET_KIT_LIB_BIP39_H

#include <string>

class Bip39 {
private:
    static std::string fullEntropyBitsToMnemonicWords(const std::string &fullEntropyString);

    static std::vector<uint8_t> getEntropyChecksum(std::vector<uint8_t> &);

public:
    static std::string entropyToMnemonic(std::vector<uint8_t> &entropy);

    static std::vector<uint8_t> mnemonicToSeed(std::string);
};

#endif //WALLET_KIT_LIB_BIP39_H
