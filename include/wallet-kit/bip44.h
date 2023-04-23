//
// Created by Ariel Saldana on 4/5/23.
//

#ifndef WALLET_KIT_LIB_BIP44_H
#define WALLET_KIT_LIB_BIP44_H

#include <string>
#include "coin_type.h"

class Bip44 {
    uint32_t purpose = 44;
    CoinType coinType;
    uint32_t account;
    uint32_t change;

public:
    explicit Bip44(
            const CoinType &coinType,
            const uint32_t &account,
            const uint32_t &change
    );

    [[nodiscard]] std::string generatePath(const uint32_t &addressIndex) const;
};

#endif //WALLET_KIT_LIB_BIP44_H
