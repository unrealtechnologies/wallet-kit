#ifndef WALLET_KIT_TO_BINARY_H
#define WALLET_KIT_TO_BINARY_H

#include <iostream>

std::string charArrayToBinary(uint8_t* str, size_t len, size_t finalStringLength);
std::string hexStringToBinary(const std::string& hexString);
//std::string charArrayToBinary(uint8_t*, size_t, size_t);

#endif //WALLET_KIT_TO_BINARY_H
