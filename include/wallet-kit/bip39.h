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
    static const int numberOfBitsPerWord = 11;
    static const int minMnemonicWords = 12;
    static const int maxMnemonicWords = 24;
    static const int mnemonicWordGroupSize = 4;

    static std::string entropyToMnemonic(std::vector<uint8_t> &entropy);
    static bool validateMnemonic(const std::string &);
    static std::vector<uint8_t> mnemonicToSeed(std::string, const std::string&);
    static std::vector<uint8_t> mnemonicToSeed(const std::string&);
    static std::vector<uint16_t> seedStringToWordIndexVector(const std::vector<std::string> &);
};

#endif //WALLET_KIT_LIB_BIP39_H
