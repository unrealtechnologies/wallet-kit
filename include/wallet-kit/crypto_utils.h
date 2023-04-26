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

#ifndef WALLET_KIT_LIB_CRYPTO_UTILS_H
#define WALLET_KIT_LIB_CRYPTO_UTILS_H

#include <vector>
#include <botan/base58.h>


namespace WalletKitCryptoUtils {
    uint32_t htobe32(uint32_t x);

    std::vector<uint8_t> uint32ToBigEndian(uint32_t num);

    std::vector<uint8_t> doubleSha256(std::vector<uint8_t> &data);

    std::vector<uint8_t> hmac512(const std::vector<uint8_t> &msg, const std::vector<uint8_t> &key);

    std::vector<uint8_t> sha256(const std::vector<uint8_t> &key);

    std::vector<uint8_t> ripemd160(const std::vector<uint8_t> &key);

    std::vector<uint8_t> generatePublicKey(const std::vector<uint8_t> &key, bool compressed = true);

    std::vector<uint8_t> generatePrivateKey(const std::vector<uint8_t> &key, const std::vector<uint8_t> &tweak);

    std::string base58Encode(std::vector<uint8_t> &data);

    Botan::secure_vector<uint8_t> keccak256(std::vector<uint8_t> &data);

    Botan::secure_vector<uint8_t> keccak256(const std::string &data);

    std::vector<uint8_t> generateEntropy(uint32_t length);
}

#endif //WALLET_KIT_LIB_CRYPTO_UTILS_H
