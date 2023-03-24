//
// Created by Ariel Saldana on 3/23/23.
//

#ifndef WALLET_KIT_DERIVE_CHECKSUM_BITS_H
#define WALLET_KIT_DERIVE_CHECKSUM_BITS_H

#include <iostream>
#include "../../third-party/sha256/sha256.h"
#include "to_binary.h"
#include <bitset>
#include <iostream>
#include <string>

//Take the binary representation of the entropy (i.e. a sequence of 0's and 1's) and concatenate it with a checksum bit
// sequence, initially set to zero. The length of the combined sequence should be a multiple of 32 bits.
//
//Compute the SHA256 hash of the combined sequence of bits, resulting in a 256-bit hash.
//
//Take the first n bits of the hash, where n is the checksum length. The checksum length is equal to one-half of the
// entropy length, in bits. For example, if the entropy length is 128 bits, the checksum length is 64 bits.
//
//Append the n bits obtained in step 3 to the original binary sequence of the entropy, to form a new binary sequence.
//
//Divide the new binary sequence into groups of 11 bits, and map each group to a corresponding word from the BIP39
// wordlist. There will be a total of m words, where m is equal to (n + entropy_length) / 11.
//
//The resulting list of words is the BIP39 mnemonic phrase for the given entropy.
//
//To summarize, the BIP39 checksum function takes the binary representation of the entropy and adds a checksum to it,
// by computing a SHA256 hash and taking the first n bits of the hash as the checksum. The resulting sequence is divided
// into groups of 11 bits, and each group is mapped to a corresponding word from the BIP39 wordlist to form the mnemonic
// phrase.

inline static std::string deriveChecksumBits(const uint8_t* entropyBytes, size_t entropyLength) {
    if (entropyLength != 16 && entropyLength != 32) {
        throw std::invalid_argument("deriveChecksumBits entropy length must be 16 or 32");
    }

    // Compute the SHA256 hash of the entropy bytes
    SHA256 sha;
    sha.update(entropyBytes, entropyLength);
    uint8_t * digest = sha.digest();

    // Convert the SHA256 hash to a binary string
    std::string sha256_str = SHA256::toString(digest);
    std::string sha256_binary_str = hex_string_to_binary(sha256_str);

    // Calculate the number of checksum bits required
    size_t checksum_bits_length = entropyLength == 32 ? 8 : 4;

    // Extract the first `checksum_bits_length` bits of the SHA256 hash as the checksum bits
    std::string checksum_bits = sha256_binary_str.substr(0, checksum_bits_length);

    return checksum_bits;
}

#endif //WALLET_KIT_DERIVE_CHECKSUM_BITS_H
