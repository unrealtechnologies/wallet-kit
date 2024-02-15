/*
 * This source code is the property of Unreal Technologies.
 *
 * Copyright (c) [2023] Unreal Technologies.
 * All rights reserved.
 *
 * Author: Ariel Saldana https://github.com/ArielSaldana
 *
 * This source code is licensed under the Apache License Version 2.0 license
 * found in the LICENSE file in the root directory of this source tree. By
 * downloading, copying, installing or using this source code, you agree to the
 * terms and conditions of the license.
 *
 * THIS SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOURCE CODE OR THE USE OR OTHER
 * DEALINGS IN THE SOURCE CODE.
 */

#ifndef WALLET_KIT_LIB_BIP39_H
#define WALLET_KIT_LIB_BIP39_H

#include <string>

/**
 * @brief A class that provides functions for working with BIP39 mnemonics.
 */
class Bip39 {
private:
  /**
   * @brief Converts a string of full entropy bits to a string of BIP39 mnemonic
   * words.
   * @param fullEntropyString A string representing the full entropy bits.
   * @return A string of BIP39 mnemonic words.
   */
  static std::string
  fullEntropyBitsToMnemonicWords(const std::string &fullEntropyString);

  /**
   * @brief Calculates the entropy checksum for a given vector of bytes.
   * @param entropy A vector of bytes representing the entropy.
   * @return A vector of bytes representing the checksum.
   */
  static std::vector<uint8_t> getEntropyChecksum(std::vector<uint8_t> &entropy);

public:
  static constexpr int numberOfBitsPerWord = 11;
  static constexpr int minMnemonicWords = 12;
  static constexpr int maxMnemonicWords = 24;
  static constexpr int mnemonicWordGroupSize = 4;
  static constexpr int entropyBytesMinLength = 16;
  static constexpr int entropyBytesMaxLength = 32;
  static constexpr int mnemonicEncodeBitsSize = 32;
  static constexpr int bitsInByte = 8;

  /**
   * @brief Converts a vector of bytes representing entropy to a string of BIP39
   * mnemonic words.
   * @param entropy A vector of bytes representing the entropy.
   * @return A string of BIP39 mnemonic words.
   */
  static std::string entropyToMnemonic(std::vector<uint8_t> &entropy);

  /**
   * @brief Validates whether a given string is a valid BIP39 mnemonic.
   * @param mnemonic A string representing the BIP39 mnemonic.
   * @return True if the string is a valid BIP39 mnemonic, false otherwise.
   */
  static bool validateMnemonic(const std::string &mnemonic);

  /**
   * @brief Converts a BIP39 mnemonic and passphrase to a seed.
   * @param mnemonic A string representing the BIP39 mnemonic.
   * @param passphrase A string representing the passphrase.
   * @return A vector of bytes representing the seed.
   */
  static std::vector<uint8_t> mnemonicToSeed(std::string mnemonic,
                                             const std::string &passphrase);

  /**
   * @brief Converts a BIP39 mnemonic to a seed using an empty passphrase.
   * @param mnemonic A string representing the BIP39 mnemonic.
   * @return A vector of bytes representing the seed.
   */
  static std::vector<uint8_t> mnemonicToSeed(const std::string &mnemonic);

  /**
   * @brief Converts a vector of BIP39 mnemonic words to a vector of word
   * indices.
   * @param words A vector of strings representing the BIP39 mnemonic words.
   * @return A vector of uint16_t values representing the word indices.
   */
  static std::vector<uint16_t>
  seedStringToWordIndexVector(const std::vector<std::string> &words);
};

#endif // WALLET_KIT_LIB_BIP39_H
