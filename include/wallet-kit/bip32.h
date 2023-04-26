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

#ifndef WALLET_KIT_LIB_BIP32_H
#define WALLET_KIT_LIB_BIP32_H

#include "extended_key.h"
#include "chain_node.h"

/**
 * @brief A class that provides functions for working with BIP32 hierarchical deterministic keys.
 */
class Bip32 {
public:
    /**
     * @brief Derives a chain of extended keys from a given seed.
     * @param seed A vector of bytes representing the seed.
     * @return A unique pointer to the root of the chain of extended keys.
     */
    static std::unique_ptr<ChainNode> fromSeed(std::vector<uint8_t> &seed);

    /**
     * @brief Parses a BIP32 path string into a vector of uint32_t values.
     * @param path A string representing the BIP32 path.
     * @return A vector of uint32_t values representing the parsed BIP32 path.
     */
    static std::vector<uint32_t> parsePath(std::string &path);
};

#endif //WALLET_KIT_LIB_BIP32_H
