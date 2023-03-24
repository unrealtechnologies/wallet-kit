//
// Created by Ariel Saldana on 3/23/23.
//

#ifndef WALLET_KIT_TO_HEX_H
#define WALLET_KIT_TO_HEX_H

#include <iostream>
#include <sstream>
#include <iomanip>

inline std::string to_hex(char* str, size_t len) {
    std::stringstream ss;
    for(int i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0')  <<  (unsigned int)(unsigned char)str[i];
    }
    std::string mystr = ss.str();
    return mystr;
}

inline std::string to_hex(uint8_t * str, size_t len) {
    std::stringstream ss;
    for(int i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0')  <<  (unsigned int)(unsigned char)str[i];
    }
    std::string mystr = ss.str();
    return mystr;
}


#endif //WALLET_KIT_TO_HEX_H
