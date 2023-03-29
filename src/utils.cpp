//
// Created by Ariel Saldana on 3/26/23.
//

#include <utils.h>

namespace walletKitUtils {

    std::string to_hex(uint8_t * str, size_t len) {
        std::stringstream ss;
        for(int i = 0; i < len; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0')  <<  (unsigned int)(unsigned char)str[i];
        }
        std::string mystr = ss.str();
        return mystr;
    }

    std::string to_hex(std::vector<uint8_t> &vec, const size_t len) {
        std::stringstream ss;
        for(int i = 0; i < len; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0')  <<  (unsigned int)(unsigned char)vec[i];
        }
        std::string mystr = ss.str();
        return mystr;
    }

    std::string vecToBinaryString(const std::vector<uint8_t>& vec) {
        std::ostringstream oss;
        for (const auto& byte : vec) {
            oss << std::bitset<8>(byte);
        }
        return oss.str();
    }
//
    std::vector<uint8_t> hexStringToBytes(const std::string &hexString) {
        std::vector<uint8_t> bytes;

        for (size_t i = 0; i < hexString.length(); i += 2) {
            std::string byteString = hexString.substr(i, 2);
            uint8_t byte = (uint8_t) strtol(byteString.c_str(), nullptr, 16);
            bytes.push_back(byte);
        }

        return bytes;
    }

    std::vector<std::string> split(const std::string &str, int len) {
        std::vector<std::string> entries;
        for (std::string::const_iterator it(str.begin()); it != str.end();) {
            auto nbChar = std::min(len, (int) std::distance(it, str.end()));
            entries.emplace_back(it, it + nbChar);
            it = it + nbChar;
        };
        return entries;
    }

    std::string charArrayToBinary(uint8_t *input, size_t inputSize, size_t finalStringLength) {
        size_t size = inputSize;
        std::string binaryStr;
        for (int i = 0; i < size; i++) {
            std::bitset<8> binary_char(input[i]); // convert char to 8-bit binary string
            binaryStr += binary_char.to_string(); // concatenate binary string to result
        }
        return binaryStr.substr(0, finalStringLength);
    }

    std::string hexStringToBinary(const std::string &hexString) {
        std::string binary_string;
        for (char const &c: hexString) {
            std::string binary = std::bitset<4>(std::stoi(std::string(1, c), 0, 16)).to_string();
            binary_string += binary;
        }
        return binary_string;
    }
}
