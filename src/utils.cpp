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

#include "wallet-kit/utils.h"
#include <iomanip>
#include <sstream>
#include <bitset>

namespace WalletKitUtils {

    std::string toHex(uint8_t *str, size_t len) {
        std::stringstream ss;
        for (int i = 0; i < len; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (unsigned int) (unsigned char) str[i];
        }
        return ss.str();
    }

    std::string toHex(std::vector<uint8_t> &vec, size_t len) {
        std::stringstream ss;
        for (int i = 0; i < len; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (unsigned int) (unsigned char) vec[i];
        }
        return ss.str();
    }

    std::string vecToBinaryString(const std::vector<uint8_t> &vec) {
        std::ostringstream oss;
        for (const auto &byte: vec) {
            oss << std::bitset<8>(byte);
        }
        return oss.str();
    }

    std::string strToBinaryString(const std::string &str) {
        std::ostringstream oss;
        for (const auto byte: str) {
          oss << std::bitset<8>(byte);
        }
        return oss.str();
    }

    std::string uint16ToBinary(uint16_t value, int bitsLength) {
        std::bitset<16> bits(value); // convert value to bitset
        std::string str = bits.to_string().substr(16 - bitsLength); // extract the least significant bits
        return str;
    }

//
    std::vector<uint8_t> hexStringToBytes(const std::string &hexString) {
        std::vector<uint8_t> bytes;

        for (size_t i = 0; i < hexString.length(); i += 2) {
            std::string byteString = hexString.substr(i, 2);
            auto byte = (uint8_t) strtol(byteString.c_str(), nullptr, 16);
            bytes.push_back(byte);
        }

        return bytes;
    }

    std::vector<std::string> split(const std::string &str, int len) {
        std::vector<std::string> entries;
        for (std::string::const_iterator it(str.begin()); it != str.end();) {
            auto nbChar = std::min(len, (int) std::distance(it, str.end()));
            entries.emplace_back(it, it + nbChar);
            it = it + nbChar;
        };
        return entries;
    }

    std::string charArrayToBinary(uint8_t *input, size_t inputSize, size_t finalStringLength) {
        std::string binaryStr;
        for (int i = 0; i < inputSize; i++) {
            std::bitset<8> binary_char(input[i]); // convert char to 8-bit binary string
            binaryStr += binary_char.to_string(); // concatenate binary string to result
        }
        return binaryStr.substr(0, finalStringLength);
    }

    std::string hexStringToBinary(const std::string &hexString) {
        std::string binaryString;
        for (char const &c: hexString) {
            std::string binary = std::bitset<8>(std::stoi(std::string(1, c), nullptr, 16)).to_string();
            binaryString += binary;
        }
        return binaryString;
    }

    std::vector<std::string> split(const std::string &s, const std::string &delimiter) {
        size_t posStart = 0, posEnd, delimLen = delimiter.length();
        std::string token;
        std::vector<std::string> res;

        while ((posEnd = s.find(delimiter, posStart)) != std::string::npos) {
            token = s.substr(posStart, posEnd - posStart);
            posStart = posEnd + delimLen;
            res.push_back(token);
        }

        res.push_back(s.substr(posStart));
        return res;
    }
}
