//
// Created by Ariel Saldana on 3/26/23.
//

#include <wallet-kit/bip32.h>
#include <wallet-kit/cryptography/crypto_utils.h>

std::unique_ptr<ChainNode> Bip32::fromSeed(std::vector<uint8_t> &seed) {
    std::string keyString = "Bitcoin seed";
    std::vector<uint8_t> key(keyString.begin(), keyString.end());
    auto extendedKeyRaw = WalletKitCryptoUtils::hmac512(seed, key);
    uint32_t extendedKeyHalfwayIndex = extendedKeyRaw.size() / 2;

    // default chain node context
    std::shared_ptr<ChainNodeContext> context(new ChainNodeContext(0, 0, 0));

    // private key
    std::unique_ptr<ExtendedKey> extendedPrivateKey(new ExtendedKey());
//    std::unique_ptr<ExtendedKey> extendedPrivateKey(new ExtendedKey());
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
            new ChainNode(nullptr, nullptr
//                    std::move(extendedPrivateKey),
//                    std::move(extendedPublicKey)
            )
    );

    std::tuple<std::unique_ptr<ExtendedKey>, std::unique_ptr<ExtendedKey>> keyTuple(
            std::move(extendedPrivateKey),
            std::move(extendedPublicKey)
    );


    chainNode->indexes.insert(std::make_pair(0, std::move(keyTuple)));

    return chainNode;
}