#include "to_binary.h"
#include <sstream>

std::string char_array_to_binary(char* str, size_t len) {
    size_t size = len;
    std::string binary_str = "";
    for (int i = 0; i < size; i++) {
        std::bitset<8> binary_char(str[i]); // convert char to 8-bit binary string
        binary_str += binary_char.to_string(); // concatenate binary string to result
    }
    return binary_str;
}

std::string char_array_to_binary(uint8_t* str, size_t len) {
    size_t size = len;
    std::string binary_str = "";
    for (int i = 0; i < size; i++) {
        std::bitset<8> binary_char(str[i]); // convert char to 8-bit binary string
        binary_str += binary_char.to_string(); // concatenate binary string to result
    }
    return binary_str;
}

std::string hex_string_to_binary(std::string hex_string) {
    std::string binary_string;
    for (char const &c: hex_string) {
        std::string binary = std::bitset<4>(std::stoi(std::string(1, c), 0, 16)).to_string();
        binary_string += binary;
    }
    return binary_string;
//    std::stringstream ss;
//    for (auto c : hex_string) {
//        uint8_t hex_value;
//        std::stringstream hex_ss;
//        hex_ss << c;
//        hex_ss >> std::hex >> hex_value;
//        std::bitset<4> bits(hex_value);
//        ss << bits.to_string();
//    }
//    std::string binary_string = ss.str();
//    return binary_string;
}
