#include <iostream>

#include "kit/bip39/wordlist.h"
#include "third-party/duthomhas/csprng.hpp"
#include "kit/bip39/generate_entropy.h"
#include "third-party/fastpbkdf2/fastpbkdf2.h"
#include "kit/bip39/bip39.h"
#include "kit/bip32/bip32.h"

int main() {
    uint8_t *entropy = generate_entropy_uint8(32);

    auto bip39Seed = Bip39::generateSeedWithEntropyRaw(entropy, 32U);
    std::cout << "bip39Seed: " << bip39Seed << std::endl;


    auto b32 = new bip32();
    b32->deriveMainKeyAndChainCode(reinterpret_cast<uint8_t (&)[64]>(bip39Seed),
                                   reinterpret_cast<uint8_t &>(bip39Seed),
                                   reinterpret_cast<uint8_t &>(bip39Seed));



    delete[] entropy;
    delete [] bip39Seed;
    delete b32;

    return 0;
}

//int main() {
//    uint8_t * entropy = generate_entropy_uint8(32);
//    auto entropyHex = to_hex(entropy, 32);
//    auto entropyBits = charArrayToBinary(entropy, 32);
//
//
//    if (entropyHex.length() != 64) {
//        std::cout << "ERROR with HEX" << std::endl;
//    }
//
//    if (entropyBits.length() != 256) {
//        std::cout << "ERROR with BINARY" << std::endl;
//    }
//
//    std::cout << "entropy str: " << entropy << "\n";
//    std::cout << "entropy hex str: " << entropyHex << "\n";
//    std::cout << "entropy binary str: " << entropyBits << "\n";
//
//
////    auto checksumBits = deriveChecksumBits(entropyBits);
//    auto checksumBitsWithEntropy = deriveChecksumBits(entropy, 32);
////    std::cout << "checksumBits: " << checksumBits << "\n";
//    std::cout << "checksumBitsWithEntropy: " << checksumBitsWithEntropy << "\n";
//
//    auto full_entropy_string = entropyBits + checksumBitsWithEntropy;
//
//    std::cout << "full_entropy_string: " << full_entropy_string << std::endl;
//
//    if ( full_entropy_string.length() % 11 != 0 ) {
//        std::cout << "ERROR with entropy string w/ checksum" << std::endl;
//    }
//
//    auto words_binary_arr = split(full_entropy_string, 11);
//
//    std::stringstream seed_string_stream;
//    for (std::string const binaryString: words_binary_arr) {
//        auto int_value = stoi(binaryString, 0, 2);
//        seed_string_stream << EnglishWordList[int_value] << " ";
//    }
//
//
//    std::string mystr = seed_string_stream.str();
//    // remove the last space
//    mystr.pop_back();
//    std::cout << "mnemonic: " << mystr<< std::endl;
//
//    const uint8_t *pw = (const uint8_t *)reinterpret_cast<const uint8_t*>(mystr.data());
//    size_t npw = mystr.length();
//    const uint8_t *salt = (const uint8_t *)"mnemonic";
//    size_t nsalt = strlen("mnemonic");
//    uint32_t iterations = 2048;
//    uint8_t out[64];
//
//    fastpbkdf2_hmac_sha512(pw, npw, salt, nsalt, iterations, out, sizeof(out));
//
//    std::cout << "BIP39 Seed" << to_hex(out, 64) << std::endl;
//
//    // fastpbkdf2_hmac_sha512
//    delete[] entropy;
//    return 0;
//}
