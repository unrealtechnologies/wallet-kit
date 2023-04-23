//
// Created by Ariel Saldana on 4/5/23.
//

#ifndef WALLET_KIT_LIB_BIP44_H
#define WALLET_KIT_LIB_BIP44_H

#include <string>
#include "coin_type.h"

/**
 * @brief The Bip44 class provides functionality for generating BIP44 paths.
 */
class Bip44 {
    uint32_t purpose = 44; /**< The purpose value of the BIP44 path. */
    CoinType coinType; /**< The coin type of the BIP44 path. */
    uint32_t account; /**< The account number of the BIP44 path. */
    uint32_t change; /**< The change value of the BIP44 path. */

public:
    /**
     * @brief Constructs a new Bip44 object.
     * @param coinType The coin type of the BIP44 path.
     * @param account The account number of the BIP44 path.
     * @param change The change value of the BIP44 path.
     */
    explicit Bip44(
            const CoinType &coinType,
            const uint32_t &account,
            const uint32_t &change
    );

    /**
     * @brief Generates a BIP44 path for a given address index.
     * @param addressIndex The address index.
     * @return The generated BIP44 path.
     */
    [[nodiscard]] std::string generatePath(const uint32_t &addressIndex) const;
};

#endif //WALLET_KIT_LIB_BIP44_H
