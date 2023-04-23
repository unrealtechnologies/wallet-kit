//
// Created by Ariel Saldana on 4/5/23.
//

#include "wallet-kit/bip44.h"
#include "wallet-kit/coin_type.h"

Bip44::Bip44(
        const CoinType &coinType,
        const uint32_t &account,
        const uint32_t &change
) : coinType(coinType), account(account), change(change) {}

std::string Bip44::generatePath(const uint32_t &addressIndex) const {
    std::string path = "m/" +
                       std::to_string(this->purpose) +
                       "'/" +
                       std::to_string(coinType) +
                       "'/" +
                       std::to_string(account) +
                       "'/" +
                       std::to_string(change) +
                       "/" + std::to_string(addressIndex
    );

    return path;
}
