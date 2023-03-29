//
// Created by Ariel Saldana on 3/26/23.
//

#include <iostream>
#include <sstream>
#include <vector>
#include <iomanip>

namespace walletKitUtils {

    std::string to_hex(uint8_t * str, size_t len);

    std::string to_hex(std::vector<uint8_t> &vec, size_t len);

    std::string vecToBinaryString(const std::vector<uint8_t>& vec);

    std::vector<uint8_t> hexStringToBytes(const std::string &hexString);

    std::vector<std::string> split(const std::string &str, int len);

    std::string charArrayToBinary(uint8_t *input, size_t inputSize, size_t finalStringLength);

    std::string hexStringToBinary(const std::string &hexString);
}
