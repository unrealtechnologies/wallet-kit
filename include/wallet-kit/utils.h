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

#include <iostream>
#include <vector>

namespace WalletKitUtils {

    std::string toHex(uint8_t *str, size_t len);

    std::string toHex(std::vector<uint8_t> &vec, size_t len);

    std::string vecToBinaryString(const std::vector<uint8_t> &vec);

    std::vector<uint8_t> hexStringToBytes(const std::string &hexString);

    std::vector<std::string> split(const std::string &str, int len);

    std::string charArrayToBinary(uint8_t *input, size_t inputSize, size_t finalStringLength);

    std::string hexStringToBinary(const std::string &hexString);

    std::vector<std::string> split(const std::string &s, const std::string &delimiter);

    std::string strToBinaryString(const std::string &str);

    std::string uint16ToBinary(uint16_t value, int bitsLength);
}
