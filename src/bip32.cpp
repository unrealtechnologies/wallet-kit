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

#include "wallet-kit/bip32.h"
#include "wallet-kit/crypto_utils.h"
#include "wallet-kit/utils.h"

std::unique_ptr<ChainNode> Bip32::fromSeed(std::vector<uint8_t> &seed) {
    std::string keyString = "Bitcoin seed";
    std::vector<uint8_t> key(keyString.begin(), keyString.end());
    auto extendedKeyRaw = WalletKitCryptoUtils::hmac512(seed, key);
    uint32_t extendedKeyHalfwayIndex = extendedKeyRaw.size() / 2;

    // default chain node context
    std::shared_ptr<ChainNodeContext> context(new ChainNodeContext(0, 0, 0));

    // private key
    std::unique_ptr<ExtendedKey> extendedPrivateKey(new ExtendedKey());
    extendedPrivateKey->context = context;
    extendedPrivateKey->key = std::vector<uint8_t>(
            extendedKeyRaw.begin(),
            extendedKeyRaw.begin() + extendedKeyHalfwayIndex
    );
    extendedPrivateKey->chainCode = std::vector<uint8_t>(
            extendedKeyRaw.begin() + extendedKeyHalfwayIndex,
            extendedKeyRaw.end()
    );

    auto extendedPublicKey = extendedPrivateKey->derivePublicChildKey();

    std::unique_ptr<ChainNode> chainNode(
            new ChainNode()
    );

    std::tuple<std::unique_ptr<ExtendedKey>, std::unique_ptr<ExtendedKey>> keyTuple(
            std::move(extendedPrivateKey),
            std::move(extendedPublicKey)
    );

    chainNode->indexes.insert(std::make_pair(0x80000000, std::move(keyTuple)));

    return chainNode;
}

// takes a path like /44'/0'/0'/0/0 and returns a vector of uint32_t
std::vector<uint32_t> Bip32::parsePath(std::string &strPath) {
    auto delimiter = "/";
    auto pathVector = WalletKitUtils::split(strPath, delimiter);
    std::vector<uint32_t> arrPath;

    for (auto &path: pathVector) {
        if (path == "m") {
            continue;
        }

        if (path.find("'") != std::string::npos) {
            path = path.substr(0, path.length() - 1);
            path = std::to_string(std::stoi(path) + 0x80000000);
            arrPath.push_back(std::stol(path));
        } else {
            arrPath.push_back(std::stol(path));
        }
    }

    return arrPath;
}

