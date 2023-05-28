/*
 * This source code is the property of Unreal Technologies.
 *
 * Copyright (c) [2023] Unreal Technologies.
 * All rights reserved.
 *
 * Author: Ariel Saldana https://github.com/ArielSaldana
 *
 * This source code is licensed under the Apache License Version 2.0 license found in the
 * LICENSE file in the root directory of this source tree. By downloading,
 * copying, installing or using this source code, you agree to the terms and
 * conditions of the license.
 *
 * THIS SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOURCE CODE OR THE USE OR OTHER
 * DEALINGS IN THE SOURCE CODE.
 */

#ifndef WALLET_KIT_LIB_BIP44_H
#define WALLET_KIT_LIB_BIP44_H

#include <string>
#include "coin_type.h"
#include <cstdint>

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
