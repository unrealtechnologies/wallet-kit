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

#ifndef WALLET_KIT_LIB_EXTENDED_KEY_H
#define WALLET_KIT_LIB_EXTENDED_KEY_H

#include <vector>
#include "chain_node_context.h"
#include <string>
#include <memory>

// An extended key is defined as a construct of (k, c) k being the normal key, and c being the chaincode.
struct ExtendedKey {
    static const int privateKeyLength = 32;
    static const int publicKeyLength = 33;
    static const int ethereumAddressByteSize = 20;
    static const size_t uint32ByteSize = 4;

    std::shared_ptr<ChainNodeContext> context;
    std::vector<uint8_t> key;
    std::vector<uint8_t> chainCode;

    [[nodiscard]]
    std::string toBase58();

    [[nodiscard]]
    std::vector<uint8_t> serialize();

    [[nodiscard]]
    std::vector<uint8_t> fingerPrint() const;

    [[nodiscard]]
    std::unique_ptr<ExtendedKey> derivePublicChildKey(bool compressed = true) const;

    [[nodiscard]]
    std::unique_ptr<ExtendedKey> derivePrivateChildKey(uint32_t index, uint32_t fingerprint, bool hardened);

    [[nodiscard]]
    std::unique_ptr<ExtendedKey> derivePublicChildKeyUncompressed() const;

    [[nodiscard]]
    std::string deriveAddress() const;
};


#endif //WALLET_KIT_LIB_EXTENDED_KEY_H
