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

#ifndef WALLET_KIT_LIB_CHAIN_NODE_CONTEXT_H
#define WALLET_KIT_LIB_CHAIN_NODE_CONTEXT_H

#include <cstdint>
/**
 * @brief The ChainNodeContext struct represents context information for a node in a chain.
 */
struct ChainNodeContext {
    uint8_t depth;
    uint32_t fingerprint;
    uint32_t childNumber;

    /**
     * @brief Constructs a ChainNodeContext object with the specified parameters.
     * @param depth The depth of the node in the chain.
     * @param fingerprint The fingerprint of the node.
     * @param childNumber The child number of the node.
     */
    ChainNodeContext(uint8_t depth, uint32_t fingerprint, uint32_t childNumber);
};

#endif //WALLET_KIT_LIB_CHAIN_NODE_CONTEXT_H
