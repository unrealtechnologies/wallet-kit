//
// Created by Ariel Saldana on 3/26/23.
//
#include <iostream>
#include <vector>

namespace WalletKitUtils {

    std::string toHex(uint8_t *str, size_t len);

    std::string toHex(std::vector<uint8_t> &vec, size_t len);

    std::string vecToBinaryString(const std::vector<uint8_t> &vec);

    std::vector<uint8_t> hexStringToBytes(const std::string &hexString);

    std::vector<std::string> split(const std::string &str, int len);

    std::string charArrayToBinary(uint8_t *input, size_t inputSize, size_t finalStringLength);

    std::string hexStringToBinary(const std::string &hexString);

    std::vector<std::string> split(const std::string &s, const std::string &delimiter);

    std::string strToBinaryString(const std::string &str);

    std::string uint16ToBinary(uint16_t value, int bitsLength);
}
