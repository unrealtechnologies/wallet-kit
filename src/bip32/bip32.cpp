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
            new ChainNode()
    );

    std::tuple<std::unique_ptr<ExtendedKey>, std::unique_ptr<ExtendedKey>> keyTuple(
            std::move(extendedPrivateKey),
            std::move(extendedPublicKey)
    );

    chainNode->indexes.insert(std::make_pair(0x80000000, std::move(keyTuple)));

    return chainNode;
}


// for string delimiter todo: move this to a utils file
std::vector<std::string> split(const std::string &s, const std::string &delimiter) {
    size_t pos_start = 0, pos_end, delim_len = delimiter.length();
    std::string token;
    std::vector<std::string> res;

    while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos) {
        token = s.substr(pos_start, pos_end - pos_start);
        pos_start = pos_end + delim_len;
        res.push_back(token);
    }

    res.push_back(s.substr(pos_start));
    return res;
}

// takes a path like /44'/0'/0'/0/0 and returns a vector of uint32_t
std::vector<uint32_t> Bip32::parsePath(std::string &strPath) {
    auto delimiter = "/";
    auto pathVector = split(strPath, delimiter);
    std::vector<uint32_t> arrPath;

    for (auto &path: pathVector) {
        if (path == "m") {
//            arrPath.push_back(0x80000000);
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

