#include <iostream>

#include "kit/bip39/wordlist.h"
#include "third-party/duthomhas/csprng.hpp"

#include "kit/bip39/generate_entropy.h"


int main() {
    char *m = generate_entropy(32);
    std::cout << m << "\n";
    std::cout << strlen(m) << "\n";
    delete[] m;

    return 0;
}
