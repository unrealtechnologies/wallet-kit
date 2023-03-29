//
// Created by Ariel Saldana on 3/28/23.
//

#include "wallet-kit/bip32/extended_key.h"
#include <vector>

std::string ExtendedKey::toBase58() {
    static const std::vector<uint8_t> version = {0x04, 0x88, 0xAD, 0xE4};
    static const std::vector<uint8_t>depth= {0x00};
    static const std::vector<uint8_t> fingerprint = {0x00, 0x00, 0x00, 0x00};
    static const std::vector<uint8_t> childNumber = {0x00, 0x00, 0x00, 0x00};

    return std::string();
}

