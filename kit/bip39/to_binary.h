#ifndef WALLET_KIT_TO_BINARY_H
#define WALLET_KIT_TO_BINARY_H

#include <iostream>

std::string char_array_to_binary(char*, size_t);
std::string charArrayToBinary(uint8_t* str, size_t len, size_t finalStringLength);
std::string char_array_to_binary(uint8_t*, size_t);
std::string hex_string_to_binary(std::string);
//std::string charArrayToBinary(uint8_t*, size_t, size_t);

#endif //WALLET_KIT_TO_BINARY_H
