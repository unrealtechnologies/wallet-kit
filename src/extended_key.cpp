//
// Created by Ariel Saldana on 3/28/23.
//

#include <vector>
#include <iomanip>
#include <sstream>
#include "wallet-kit/utils.h"
#include "wallet-kit/extended_key.h"
#include "wallet-kit/crypto_utils.h"

std::string ExtendedKey::toBase58() {
    if (this->context == nullptr) {
        throw std::runtime_error("ExtendedKey context is null");
    }

    auto serializedStructure = this->serialize();
    return WalletKitCryptoUtils::base58Encode(serializedStructure);
}

std::vector<uint8_t> ExtendedKey::serialize() {
    std::vector<uint8_t> structure;
    const int serializedKeyWithoutChecksumLength = 72;
    const int serializedKeyWithChecksumLength = 82;
    structure.reserve(serializedKeyWithChecksumLength);

    const std::vector<uint8_t> privateVersion = {0x04, 0x88, 0xAD, 0xE4};   // 4 bytes version
    const std::vector<uint8_t> publicVersion = {0x04, 0x88, 0xB2, 0x1E};    // 4 bytes version

    if (this->key.size() == 32) {
        structure.insert(structure.end(), privateVersion.begin(), privateVersion.end());
    } else {
        structure.insert(structure.end(), publicVersion.begin(), publicVersion.end());
    }

    structure.insert(
            structure.end(),
            reinterpret_cast<const uint8_t *>(&this->context->depth),
            reinterpret_cast<const uint8_t *>(&this->context->depth) + sizeof(this->context->depth)
    );

    std::vector<uint8_t> fingerprintBigEndianOrder = WalletKitCryptoUtils::uint32ToBigEndian(
            this->context->fingerprint
    );

    structure.insert(
            structure.end(),
            fingerprintBigEndianOrder.begin(),
            fingerprintBigEndianOrder.end()
    );

    std::vector<uint8_t> childNumberBigEndianOrder = WalletKitCryptoUtils::uint32ToBigEndian(
            this->context->childNumber
    );

    structure.insert(structure.end(), childNumberBigEndianOrder.begin(), childNumberBigEndianOrder.end());

    structure.insert(structure.end(), this->chainCode.begin(), this->chainCode.end());

    if (this->key.size() == 32) {
        structure.push_back(0x00);
    }

    structure.insert(structure.end(), this->key.begin(), this->key.end());


    // take the first 4 bytes of the double sha256 of the 78 byte structure above and append it to the structure.
    auto str = WalletKitUtils::toHex(structure, serializedKeyWithoutChecksumLength);
    std::vector<uint8_t> doubleSha256Checksum = WalletKitCryptoUtils::doubleSha256(structure);
    structure.insert(structure.end(), doubleSha256Checksum.begin(), doubleSha256Checksum.begin() + 4);

    return structure;
}

std::vector<uint8_t> ExtendedKey::fingerPrint() const {
    // Compute the first SHA256 hash
    auto firstSha256 = WalletKitCryptoUtils::sha256(this->key);
    auto outputData = WalletKitCryptoUtils::ripemd160(firstSha256);
    return {outputData.begin(), outputData.end()};
}

std::unique_ptr<ExtendedKey> ExtendedKey::derivePublicChildKey(bool compressed) const {
    auto publicKey = WalletKitCryptoUtils::generatePublicKey(this->key, compressed);

    std::unique_ptr<ExtendedKey> publicExtendedKey(new ExtendedKey());
    publicExtendedKey->key = publicKey;
    publicExtendedKey->chainCode = this->chainCode;
    publicExtendedKey->context = this->context;

    return publicExtendedKey;
}

std::unique_ptr<ExtendedKey> ExtendedKey::derivePrivateChildKey(uint32_t index, uint32_t fingerprint, bool hardened) {
    // Determine whether the child key is hardened or not
    uint32_t childIndex = index;

    if (hardened) {
        childIndex |= 0x80000000;
    }

    // Compute HMAC-SHA512 of parent key and child index
    std::vector<uint8_t> data(37);
    if (hardened) {
        data[0] = 0x00;
        std::copy(this->key.begin(), this->key.end(), data.begin() + 1);
    } else {
        auto publicKey = WalletKitCryptoUtils::generatePublicKey(this->key);
        std::copy(publicKey.begin(), publicKey.end(), data.begin());
    }
    data[33] = (childIndex >> 24) & 0xff;
    data[34] = (childIndex >> 16) & 0xff;
    data[35] = (childIndex >> 8) & 0xff;
    data[36] = childIndex & 0xff;

    auto I = WalletKitCryptoUtils::hmac512(data, this->chainCode);

    // Split HMAC output into left (IL) and right (IR) 32-byte sequences
    // (IL) is used as the tweak value, (IR) is used as the child chain code
    std::vector<uint8_t> IL(I.begin(), I.begin() + 32);
    std::vector<uint8_t> IR(I.begin() + 32, I.end());

    auto privateKey = WalletKitCryptoUtils::generatePrivateKey(this->key, IL);

    // Compute child chain code
    const std::vector<uint8_t> &childChainCode = IR;

    auto privateKeyContext = std::make_shared<ChainNodeContext>(
            ++this->context->depth,
            fingerprint,
            childIndex
    );

    // Construct child extended key
    std::unique_ptr<ExtendedKey> childExtendedKey(new ExtendedKey());
    childExtendedKey->key = privateKey;
    childExtendedKey->chainCode = childChainCode;
    childExtendedKey->context = privateKeyContext;

    return childExtendedKey;
}

std::unique_ptr<ExtendedKey> ExtendedKey::derivePublicChildKeyUncompressed() const {
    return this->derivePublicChildKey(false);
}

std::string ethereumAddressChecksum(const std::string &address) {
    // Convert the address to lowercase hexadecimal
    std::string lowercaseAddress = address.substr(2);
    std::transform(lowercaseAddress.begin(), lowercaseAddress.end(), lowercaseAddress.begin(), ::tolower);

    // Hash the lowercase address with Keccak-256
    auto hash = WalletKitCryptoUtils::keccak256(lowercaseAddress);

    // Create the checksum address by replacing each character in the original address
    // with either uppercase or lowercase depending on the corresponding character in the hash
    std::string checksumAddress = "0x";
for (int i = 0; i < lowercaseAddress.length(); i++) {
        if (((hash[i / 2] >> ((1 - i % 2) * 4)) & 0x0f) >= 8) {
            checksumAddress += toupper(lowercaseAddress[i]);
        } else {
            checksumAddress += lowercaseAddress[i];
        }
    }

    return checksumAddress;
}

std::string ExtendedKey::deriveAddress() const {
    auto uncompressedPublicKey = *this->derivePublicChildKeyUncompressed();
    std::vector<uint8_t> publicKeyWithoutPrefix(
            uncompressedPublicKey.key.begin() + 1,
            uncompressedPublicKey.key.end()
    );
    auto keccakDigestSecureVector = WalletKitCryptoUtils::keccak256(publicKeyWithoutPrefix);
    std::vector<uint8_t> keccakDigestUnSecureVector = std::vector<uint8_t>(
            keccakDigestSecureVector.begin(),
            keccakDigestSecureVector.end()
    );

    // Extract last 20 bytes of hash as Ethereum address
    std::vector<uint8_t> addressBytes(
            keccakDigestUnSecureVector.end() - 20,
            keccakDigestUnSecureVector.end()
    );
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setfill('0');
    for (auto byte: addressBytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    std::string ethereumAddress = oss.str();
    return ethereumAddressChecksum(ethereumAddress);
}


