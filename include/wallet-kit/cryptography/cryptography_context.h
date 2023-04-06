//
// Created by Ariel Saldana on 4/2/23.
//

#ifndef WALLET_KIT_LIB_CRYPTOGRAPHY_CONTEXT_H
#define WALLET_KIT_LIB_CRYPTOGRAPHY_CONTEXT_H

#include <mutex>
#include "secp256k1.h"

class CryptoContext {
public:
    static CryptoContext &getInstance();

    [[maybe_unused]] secp256k1_context *getSecp256k1Context();


private:
    secp256k1_context *ctx;
    static std::mutex mutex;

    CryptoContext();

    CryptoContext(const CryptoContext &) = delete;

    CryptoContext &operator=(const CryptoContext &) = delete;

};

#endif //WALLET_KIT_LIB_CRYPTOGRAPHY_CONTEXT_H
