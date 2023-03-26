#include <iostream>
#include <array>

#include "kit/bip39/wordlist.h"
#include "third-party/duthomhas/csprng.hpp"
#include "kit/bip39/generate_entropy.h"
#include "third-party/fastpbkdf2/fastpbkdf2.h"
#include "kit/bip39/bip39.h"
#include "kit/bip32/bip32.h"
#include "kit/bip39/to_hex.h"
#include "kit/base58.h"
#include "kit/bip39/to_binary.h"
#include "third-party/sha256/sha256.h"
#include <library.h>

uint8_t *hex_str_to_uint8(const char *string) {

    if (string == NULL)
        return NULL;

    size_t slength = strlen(string);
    if ((slength % 2) != 0) // must be even
        return NULL;

    size_t dlength = slength / 2;

    uint8_t *data = (uint8_t *) malloc(dlength);

    memset(data, 0, dlength);

    size_t index = 0;
    while (index < slength) {
        char c = string[index];
        int value = 0;
        if (c >= '0' && c <= '9')
            value = (c - '0');
        else if (c >= 'A' && c <= 'F')
            value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
            value = (10 + (c - 'a'));
        else
            return NULL;

        data[(index / 2)] += value << (((index + 1) % 2) * 4);

        index++;
    }

    return data;
}

int main() {

    hello();


//    uint8_t *entropy = generate_entropy_uint8(32);
    std::string entropyHexStr = "c94c3a10b50450a4eaeee90e45ca90f551ef08266942b4bc4ad821e517e7a24a";
    uint8_t *entropy = hex_str_to_uint8(entropyHexStr.c_str());

    std::cout << "entropy: " << to_hex(entropy, 32) << std::endl;

    auto bip39Seed = Bip39::generateSeedWithEntropyRaw(entropy, 32U);
    std::cout << "bip39Seed: " << to_hex(bip39Seed, 64) << std::endl;

    auto b32 = new bip32();

    uint8_t mainKey[32];
    uint8_t chainCode[32];
    b32->deriveMainKeyAndChainCode(
            bip39Seed,
            mainKey,
            chainCode);

    // print the root key and chaincode m'
    std::cout << "private-key: " << to_hex(mainKey, 32) << std::endl;
    std::cout << "chainCode: " << to_hex(chainCode, 32) << std::endl;

    auto pk = b32->derivePublicKey(mainKey);
    std::cout << "public key: " << to_hex(pk, 64) << std::endl;

    // serialize to get xprv key
    // uint8_t * version = [0x0488ADE4];
    static const uint8_t version[] = {0x04, 0x88, 0xAD, 0xE4};
    static const uint8_t depth[] = {0x00};
    static const uint8_t fingerprint[] = {0x00, 0x00, 0x00, 0x00};
    static const uint8_t childNumber[] = {0x00, 0x00, 0x00, 0x00};

    uint8_t *format = (uint8_t *) std::malloc(82 + 1);
    std::memcpy(&format[0], version, 4);
    std::memcpy(&format[4], depth, 1);
    std::memcpy(&format[5], fingerprint, 4);
    std::memcpy(&format[9], childNumber, 4);
    std::memcpy(&format[13], chainCode, 32);
    std::memcpy(&format[45], depth, 1);
    std::memcpy(&format[46], mainKey, 32);

    std::string out;
//    auto binary =  charArrayToBinary(format, 78, 30);

    // Allocate a char array with space for the null terminator
//    char charArray[binary.length() + 1];
    // Copy the string contents to the char array
//    std::strcpy(charArray, binary.c_str());

    for (int i = 0; i < 82; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << "0x" << (int) format[i] << ", ";
    }

    std::cout << std::endl;

    SHA256 sha;
    SHA256 sha2;

    sha.update(format, 78);
    uint8_t *firstSha = sha.digest();

    sha2.update(firstSha, 32);
    uint8_t *secondSha = sha2.digest();

    std::memcpy(&format[78], secondSha, 4);

    encode(format, 82, out);
//    encode(charArray, binary.length(), out);

//    std::cout << "binary: " << binary << std::endl;
    std::cout << "xprv: " << out << std::endl;




//    std::memcpy(&hmacKey[1], key, 32);
//    hmacKey[0] = 0x00;

    uint8_t keyM0[32];
    uint8_t chainCodeM0[32];
    b32->childKeyDerivationPrivate(mainKey, chainCode, 0U, keyM0, chainCodeM0);

    std::cout << "keyM0: " << to_hex(keyM0, 32) << std::endl;
    std::cout << "chainCodeM0: " << to_hex(chainCodeM0, 32) << std::endl;

    uint8_t keyM00[32];
    uint8_t chainCodeM00[32];
    b32->childKeyDerivationPrivate(keyM0, chainCodeM0, 0, keyM00, chainCodeM00);

    std::cout << "keyM00: " << to_hex(keyM00, 32) << std::endl;
    std::cout << "chainCodeM00: " << to_hex(chainCodeM00, 32) << std::endl;


    delete[] entropy;
    delete[] bip39Seed;
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
