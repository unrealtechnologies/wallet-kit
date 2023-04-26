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

#ifndef WALLET_KIT_LIB_CRYPTOGRAPHY_CONTEXT_H
#define WALLET_KIT_LIB_CRYPTOGRAPHY_CONTEXT_H

#include <mutex>
#include "../../build/_deps/secp256k1-src/include/secp256k1.h"

class CryptoContext {
public:
    static CryptoContext &getInstance();

    [[maybe_unused]] secp256k1_context *getSecp256K1Context();


private:
    secp256k1_context *ctx;
    static std::mutex mutex;

    CryptoContext();

    CryptoContext(const CryptoContext &) = delete;

    CryptoContext &operator=(const CryptoContext &) = delete;

};

#endif //WALLET_KIT_LIB_CRYPTOGRAPHY_CONTEXT_H
