//
// Created by Ariel Saldana on 3/26/23.
//

#ifndef WALLET_KIT_LIB_BIP39_H
#define WALLET_KIT_LIB_BIP39_H

#include <string>

/**
 * @brief A class that provides functions for working with BIP39 mnemonics.
 */
class Bip39 {
private:
    /**
     * @brief Converts a string of full entropy bits to a string of BIP39 mnemonic words.
     * @param fullEntropyString A string representing the full entropy bits.
     * @return A string of BIP39 mnemonic words.
     */
    static std::string fullEntropyBitsToMnemonicWords(const std::string &fullEntropyString);

    /**
     * @brief Calculates the entropy checksum for a given vector of bytes.
     * @param entropy A vector of bytes representing the entropy.
     * @return A vector of bytes representing the checksum.
     */
    static std::vector<uint8_t> getEntropyChecksum(std::vector<uint8_t> &);

public:
    static const int numberOfBitsPerWord = 11;
    static const int minMnemonicWords = 12;
    static const int maxMnemonicWords = 24;
    static const int mnemonicWordGroupSize = 4;

    /**
     * @brief Converts a vector of bytes representing entropy to a string of BIP39 mnemonic words.
     * @param entropy A vector of bytes representing the entropy.
     * @return A string of BIP39 mnemonic words.
     */
    static std::string entropyToMnemonic(std::vector<uint8_t> &entropy);

    /**
    * @brief Validates whether a given string is a valid BIP39 mnemonic.
    * @param mnemonic A string representing the BIP39 mnemonic.
    * @return True if the string is a valid BIP39 mnemonic, false otherwise.
    */
    static bool validateMnemonic(const std::string &);

    /**
     * @brief Converts a BIP39 mnemonic and passphrase to a seed.
     * @param mnemonic A string representing the BIP39 mnemonic.
     * @param passphrase A string representing the passphrase.
     * @return A vector of bytes representing the seed.
     */
    static std::vector<uint8_t> mnemonicToSeed(std::string, const std::string &);

    /**
     * @brief Converts a BIP39 mnemonic to a seed using an empty passphrase.
     * @param mnemonic A string representing the BIP39 mnemonic.
     * @return A vector of bytes representing the seed.
     */
    static std::vector<uint8_t> mnemonicToSeed(const std::string &);

    /**
     * @brief Converts a vector of BIP39 mnemonic words to a vector of word indices.
     * @param words A vector of strings representing the BIP39 mnemonic words.
     * @return A vector of uint16_t values representing the word indices.
     */
    static std::vector<uint16_t> seedStringToWordIndexVector(const std::vector<std::string> &);
};

#endif //WALLET_KIT_LIB_BIP39_H
