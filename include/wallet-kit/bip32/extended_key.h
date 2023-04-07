//
// Created by Ariel Saldana on 3/27/23.
//

#ifndef WALLET_KIT_LIB_EXTENDED_KEY_H
#define WALLET_KIT_LIB_EXTENDED_KEY_H

#include <vector>
#include "chain_node_context.h"

// An extended key is defined as a construct of (k, c) k being the normal key, and c being the chaincode.
struct ExtendedKey {
    std::shared_ptr<ChainNodeContext> context;
    std::vector<uint8_t> key;
    std::vector<uint8_t> chainCode;

    [[nodiscard]] std::string toBase58();

    [[nodiscard]] std::vector<uint8_t> serialize();

    [[nodiscard]] std::vector<uint8_t> fingerPrint() const;

    [[nodiscard]] std::unique_ptr<ExtendedKey> derivePublicChildKey(bool compressed = true) const;

    [[nodiscard]] std::unique_ptr<ExtendedKey> derivePrivateChildKey(uint32_t index, uint32_t fingerprint, bool hardened);

    [[nodiscard]] std::unique_ptr<ExtendedKey> derivePublicChildKeyUncompressed() const;

    [[nodiscard]] std::string deriveAddress() const;
};


#endif //WALLET_KIT_LIB_EXTENDED_KEY_H
