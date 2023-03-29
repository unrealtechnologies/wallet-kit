//
// Created by Ariel Saldana on 3/28/23.
//
#include <wallet-kit/bip32/hdw.h>

HDW::HDW(std::shared_ptr<ExtendedKey> &extendedKey) {
    this->root = *extendedKey;
}

void HDW::derivePath(std::string path) {

}
