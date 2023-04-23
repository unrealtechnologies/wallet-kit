//
// Created by Ariel Saldana on 4/2/23.
//

#include "wallet-kit/cryptography_context.h"

CryptoContext &CryptoContext::getInstance() {
    std::lock_guard<std::mutex> lock(mutex);
    static CryptoContext instance;
    return instance;
}

CryptoContext::CryptoContext() {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

secp256k1_context *CryptoContext::getSecp256K1Context() {
    return ctx;
}

std::mutex CryptoContext::mutex;