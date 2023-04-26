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

#include <utility>
#include "wallet-kit/chain_node.h"
#include "wallet-kit/bip32.h"
#include "wallet-kit/utils.h"

ChainNode::ChainNode() = default;

std::unique_ptr<ExtendedKey> ChainNode::derivePrivateChildExtendedKey(
        uint32_t parentKeyIndex,
        uint32_t childKeyIndex,
        bool hardened
) const {
    auto fingerprintVec = std::get<1>(this->indexes.find(parentKeyIndex)->second)->fingerPrint();
    uint32_t fingerprint =
            ((uint8_t) fingerprintVec[0] << 24) |
            ((uint8_t) fingerprintVec[1] << 16) |
            ((uint8_t) fingerprintVec[2] << 8) |
            ((uint8_t) fingerprintVec[3]);

    auto pKey = *std::get<0>(this->indexes.find(parentKeyIndex)->second);

    if (pKey.key.size() > 32) {
        throw std::runtime_error("private key length is greater than 32, are you trying to use a public key?");
    }

    return pKey.derivePrivateChildKey(childKeyIndex, fingerprint, hardened);
}

std::tuple<ExtendedKey, ExtendedKey> ChainNode::findNode(const std::string &path) {
    if (path.empty()) {
        throw std::runtime_error("Path is empty");
    }

    if (path == "m") {
        auto prvKey = *std::get<0>(this->indexes.find(0x80000000)->second);
        auto pubKey = *std::get<1>(this->indexes.find(0x80000000)->second);
        return std::make_tuple(prvKey, pubKey);
    }

    auto pathArr = Bip32::parsePath(const_cast<std::string &>(path));

    if (pathArr.empty()) {
        throw std::runtime_error("Path arr is empty");
    }

    return this->search(this, pathArr);
}

std::tuple<ExtendedKey, ExtendedKey> ChainNode::search(ChainNode *currentNode, const std::vector<uint32_t> &pathArr) {
    auto keyIndex = pathArr[0];
    if (pathArr.size() > 1) {

        if (keyIndex >= 0x80000000) {
            std::vector<uint32_t> subArr(pathArr.begin() + 1, pathArr.end());
            return this->search(currentNode->right.get(), subArr);
        }
    } else {
        auto prvKey = *std::get<0>(currentNode->indexes.find(keyIndex)->second);
        auto pubKey = *std::get<1>(currentNode->indexes.find(keyIndex)->second);
        return std::make_tuple(prvKey, pubKey);
    }
    return {};
}

void ChainNode::insertIndexIntoNode(
        ChainNode *node,
        uint32_t index,
        std::unique_ptr<ExtendedKey> prvKey,
        std::unique_ptr<ExtendedKey> pubKey
) {
    node->indexes.insert(
            std::make_pair(
                    index,
                    std::make_tuple(std::move(prvKey), std::move(pubKey))
            )
    );
}

std::tuple<ExtendedKey, ExtendedKey> ChainNode::derivePath(const std::string &path) {
    auto pathArr = Bip32::parsePath(const_cast<std::string &>(path));
    auto currentNode = this;
    uint32_t lastIndex = 0x80000000;
    for (auto index: pathArr) {
        auto isHardened = index >= 0x80000000;
        auto prvKey = currentNode->derivePrivateChildExtendedKey(lastIndex, index, isHardened);
        auto pubKey = prvKey->derivePublicChildKey();
        auto &childNode = (index >= 0x80000000) ? currentNode->right : currentNode->left;

        childNode = std::make_unique<ChainNode>();
        insertIndexIntoNode(childNode.get(), index, std::move(prvKey), std::move(pubKey));
        currentNode = childNode.get();
        lastIndex = index;
    }

    auto &[prvKey1, pubKey1] = currentNode->indexes.find(pathArr[pathArr.size() - 1])->second;
    return std::make_tuple(*prvKey1.get(), *pubKey1.get());
};

