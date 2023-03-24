//
// Created by Ariel Saldana on 3/22/23.
//

#include "generate_entropy.h"
#include "../../third-party/duthomhas/csprng.hpp"

// char is a signed or unsigned character data type in C and C++, depending on the implementation. It is commonly used to
// represent characters in text, and its range depends on the character set used. In most systems, a char is an 8-bit
// byte that can represent values between -128 to 127 (for signed char) or 0 to 255 (for unsigned char).
//
// uint8_t, on the other hand, is an unsigned integer data type defined in the C++ standard library's <stdint.h> header.
// It is guaranteed to be an 8-bit byte and can represent values between 0 and 255. Unlike char, it is not intended for
// use in representing characters in text, but rather for representing raw bytes of data.


char* generate_entropy(size_t len) {
    duthomhas::csprng rng;
    rng.seed("unrealwallet");
    char* r = new char[ len ];
    rng( r, len );
    return r;
};

uint8_t* generate_entropy_uint8(size_t len) {
    duthomhas::csprng rng;
    rng.seed("unrealwallet");
    uint8_t* r = new uint8_t[ len ];
    rng(r, len);
    return r;
};

std::string generate_entropy_binary_bits(size_t len) {
    auto entropy = generate_entropy(len);
    size_t size = sizeof(len) / sizeof(entropy[0]);
    std::string binary_str = "";
    for (int i = 0; i < size; i++) {
        std::bitset<8> binary_char(entropy[i]); // convert char to 8-bit binary string
        binary_str += binary_char.to_string(); // concatenate binary string to result
    }
    return binary_str;
}
