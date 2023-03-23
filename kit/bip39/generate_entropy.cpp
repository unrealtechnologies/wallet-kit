//
// Created by Ariel Saldana on 3/22/23.
//

#include "generate_entropy.h"
#include "../../third-party/duthomhas/csprng.hpp"

char * generate_entropy(size_t len) {
    duthomhas::csprng rng;
    rng.seed("unrealwallet");
    char* r = new char[ len ];
    rng( r, len );
    return r;
};
