#include "to_binary.h"
#include <sstream>

std::string charArrayToBinary(uint8_t* input, size_t inputSize, size_t finalStringLength) {
    size_t size = inputSize;
    std::string binaryStr;
    for (int i = 0; i < size; i++) {
        std::bitset<8> binary_char(input[i]); // convert char to 8-bit binary string
        binaryStr += binary_char.to_string(); // concatenate binary string to result
    }
    return binaryStr.substr(0, finalStringLength);
}

std::string hexStringToBinary(const std::string& hexString) {
    std::string binary_string;
    for (char const &c: hexString) {
        std::string binary = std::bitset<4>(std::stoi(std::string(1, c), 0, 16)).to_string();
        binary_string += binary;
    }
    return binary_string;
}
