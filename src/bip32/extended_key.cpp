//
// Created by Ariel Saldana on 3/28/23.
//

#include "wallet-kit/bip32/extended_key.h"
#include "utils.h"
#include <vector>
#include <botan/base58.h>
#include <botan/rmd160.h>
#include <botan/sha2_32.h>

std::string ExtendedKey::toBase58() {
    if (this->context == nullptr) {
        throw std::runtime_error("ExtendedKey context is null");
    }

    auto serializedStructure = this->serialize();
    auto base58EncodedString = Botan::base58_encode(serializedStructure);
    return base58EncodedString;
}

std::vector<uint8_t> ExtendedKey::serialize() {
    std::vector<uint8_t> structure;
    structure.reserve(78);

    const std::vector<uint8_t> privateVersion = {0x04, 0x88, 0xAD, 0xE4};     // 4 bytes version
    const std::vector<uint8_t> publicVersion = {0x04, 0x88, 0xB2, 0x1E};     // 4 bytes version

    if (this->key.size() == 32) {
        structure.insert(structure.end(), privateVersion.begin(), privateVersion.end());
    } else {
        structure.insert(structure.end(), publicVersion.begin(), publicVersion.end());
    }

    structure.insert(structure.end(), reinterpret_cast<const uint8_t*>(&this->context->depth), reinterpret_cast<const uint8_t*>(&this->context->depth) + sizeof(this->context->depth));
    structure.insert(structure.end(), reinterpret_cast<const uint8_t*>(&this->context->fingerprint), reinterpret_cast<const uint8_t*>(&this->context->fingerprint) + sizeof(this->context->fingerprint));
    structure.insert(structure.end(), reinterpret_cast<const uint8_t*>(&this->context->childNumber), reinterpret_cast<const uint8_t*>(&this->context->childNumber) + sizeof(this->context->childNumber));
    structure.insert(structure.end(), this->chainCode.begin(), this->chainCode.end());

    if (this->key.size() == 32) {
        structure.push_back(0x00);
    }
    structure.insert(structure.end(), this->key.begin(), this->key.end());

    // take the first 4 bytes of the double sha256 of the 78 byte structure above and append it to the structure.
    std::vector<uint8_t> doubleSha256Checksum = ExtendedKey::doubleSha256(structure);
    structure.insert(structure.end(), doubleSha256Checksum.begin(), doubleSha256Checksum.begin() + 4);

    return structure;
}

std::vector<uint8_t> ExtendedKey::doubleSha256(std::vector<uint8_t> &data) {
    // we don't need to manage the
    // lifecycle of the hash pointer,
    // commenting this out: std::unique_ptr<Botan::HashFunction> hash256(Botan::HashFunction::create("SHA-256"));
    // in favor of using Botan::SHA_256() directly.

    // compute the first sha256 hash
    auto hash256 = Botan::SHA_256();
    hash256.update(data.data(), data.size());
    auto firstSha256  = hash256.final();

    // clear for reuse
    hash256.clear();

    // compute the second sha256 hash
    hash256.update(firstSha256.data(), firstSha256.size());
    auto secondSha256 = hash256.final();

    return {secondSha256.begin(), secondSha256.end()};
}

std::vector<uint8_t> ExtendedKey::fingerPrint(const std::vector<uint8_t> &key) {
    // Compute the first SHA256 hash
    auto hash256 = Botan::SHA_256();
    hash256.update(key.data(), key.size());
    auto firstSha256 = hash256.final();

    Botan::RIPEMD_160 ripemd160;
    auto output_data = ripemd160.process(firstSha256);
    std::vector<uint8_t> ripemd160vec(output_data.begin(), output_data.end());

    return {ripemd160vec.begin(), ripemd160vec.end()};
}

