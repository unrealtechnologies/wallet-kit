#include "../include/library.h"
#include <iostream>
#include <botan/hex.h>
#include <botan/hash.h>
#include <botan/mac.h>

static std::string compute_mac(const std::string &msg, const std::vector<uint8_t> &key) {
    auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-512)");

    hmac->set_key(key);
    hmac->update(msg);

    return Botan::hex_encode(hmac->final());
}

void hello() {
    std::unique_ptr<Botan::HashFunction> hash256(Botan::HashFunction::create("SHA-256"));
    std::vector<uint8_t> buf(2048);

    std::string toHash = "hash this or else";
    std::vector<uint8_t> vec(toHash.begin(), toHash.end());

    hash256->update(vec.data(), toHash.length());

    auto hmacResult = compute_mac(toHash, vec);

    std::cout << "From Lib: SHA-256: " << Botan::hex_encode(hash256->final()) << std::endl;
    std::cout << "From Lib: HMAC512: " << hmacResult << std::endl;
}
