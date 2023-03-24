//
// Created by Ariel Saldana on 3/22/23.
//
#include <iostream>

#ifndef WALLET_KIT_GENERATE_ENTROPY_H
#define WALLET_KIT_GENERATE_ENTROPY_H

char * generate_entropy(size_t);
uint8_t* generate_entropy_uint8(size_t);
std::string generate_entropy_binary_bits(size_t len);

#endif //WALLET_KIT_GENERATE_ENTROPY_H
