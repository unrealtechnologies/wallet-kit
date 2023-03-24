#include <iostream>

#include "kit/bip39/wordlist.h"
#include "third-party/duthomhas/csprng.hpp"
#include "kit/bip39/generate_entropy.h"
#include "kit/bip39/to_binary.h"
#include "kit/bip39/derive_checksum_bits.h"
#include "kit/bip39/to_hex.h"
#include "kit/bip39/split.h"

//std::vector<std::string> split(const std::string& str, int splitLength)
//{
//    int NumSubstrings = str.length() / splitLength;
//    std::vector<std::string> ret;
//
//    for (auto i = 0; i < NumSubstrings; i++)
//    {
//        ret.push_back(str.substr(i * splitLength, splitLength));
//    }
//
//    // If there are leftover characters, create a shorter item at the end.
//    if (str.length() % splitLength != 0)
//    {
//        ret.push_back(str.substr(splitLength * NumSubstrings));
//    }
//
//
//    return ret;
//}

int main() {
//    char arr[3] = "b6";
//    std::cout << to_hex(arr, 1) << std::endl;
//    std::cout << char_array_to_binary(arr, 2) << "\n";
//    std::cout << std::bitset<8>(arr[0]).to_string() << std::endl;
//    char * entropy = generate_entropy(32);
    uint8_t * entropy = generate_entropy_uint8(32);
    auto entropyHex = to_hex(entropy, 32);
    auto entropyBits = char_array_to_binary(entropy, 32);


    if (entropyHex.length() != 64) {
        std::cout << "ERROR with HEX" << std::endl;
    }

    if (entropyBits.length() != 256) {
        std::cout << "ERROR with BINARY" << std::endl;
    }

    std::cout << "entropy str: " << entropy << "\n";
    std::cout << "entropy hex str: " << entropyHex << "\n";
    std::cout << "entropy binary str: " << entropyBits << "\n";


//    auto checksumBits = derive_checksum_bits(entropyBits);
    auto checksumBitsWithEntropy = derive_checksum_bits(entropy, 32);
//    std::cout << "checksumBits: " << checksumBits << "\n";
    std::cout << "checksumBitsWithEntropy: " << checksumBitsWithEntropy << "\n";

    auto full_entropy_string = entropyBits + checksumBitsWithEntropy;

    std::cout << "full_entropy_string: " << full_entropy_string << std::endl;

    if ( full_entropy_string.length() % 11 != 0 ) {
        std::cout << "ERROR with entropy string w/ checksum" << std::endl;
    }

    auto words_binary_arr =split(full_entropy_string, 11);

    std::cout << "Seed phrase: ";
    for (std::string const binaryString: words_binary_arr) {
        auto int_value = stoi(binaryString, 0, 2);
        std::cout << EnglishWordList[int_value] << " ";
    }


//    std::cout << strlen("1010110111011000110010010010111001001011001001010110001011100001") << std::endl;



    delete[] entropy;
    return 0;
}
