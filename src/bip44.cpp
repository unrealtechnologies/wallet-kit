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
