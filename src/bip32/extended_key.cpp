//
// Created by Ariel Saldana on 3/28/23.
//

#include "wallet-kit/bip32/extended_key.h"
#include <vector>
#include <botan/hash.h>
#include <botan/base58.h>

std::string ExtendedKey::toBase58() {
    auto serializedStructure = this->serialize();
    auto base58EncodedString = Botan::base58_encode(serializedStructure);
    return base58EncodedString;
}

std::vector<uint8_t> ExtendedKey::serialize() {
    std::vector<uint8_t> structure;
    structure.reserve(78);

    const std::vector<uint8_t> version = {0x04, 0x88, 0xAD, 0xE4};       // 4 bytes version
    const std::vector<uint8_t> depth = {0x00};                           // 1 byte depth
    const std::vector<uint8_t> fingerprint = {0x00, 0x00, 0x00, 0x00};   // 4 bytes fingerprint
    const std::vector<uint8_t> childNumber = {0x00, 0x00, 0x00, 0x00};   // 4 bytes child number

    structure.insert(structure.end(), version.begin(), version.end());
    structure.insert(structure.end(), depth.begin(), depth.end());
    structure.insert(structure.end(), fingerprint.begin(), fingerprint.end());
    structure.insert(structure.end(), childNumber.begin(), childNumber.end());
    structure.insert(structure.end(), this->chainCode.begin(), this->chainCode.end());
    structure.insert(structure.end(), depth.begin(), depth.end());
    structure.insert(structure.end(), this->key.begin(), this->key.end());

    // take the first 4 bytes of the double sha256 of the 78 byte structure above and append it to the structure.
    std::vector<uint8_t> doubleSha256Checksum = ExtendedKey::doubleSha256(structure);
    structure.insert(structure.end(), doubleSha256Checksum.begin(), doubleSha256Checksum.begin() + 4);
    return structure;
}

std::vector<uint8_t> ExtendedKey::doubleSha256(std::vector<uint8_t> &data) {
    // Compute the first SHA256 hash
    std::unique_ptr<Botan::HashFunction> hash256(Botan::HashFunction::create("SHA-256"));
    hash256->update(data.data(), data.size());
    auto firstSha256 = hash256->final();

    // Compite the second SHA256 hash
    std::unique_ptr<Botan::HashFunction> secondHash256(Botan::HashFunction::create("SHA-256"));
    secondHash256->update(firstSha256.data(), firstSha256.size());
    auto secondSha256 = secondHash256->final();

    return {secondSha256.begin(), secondSha256.end()};
}

