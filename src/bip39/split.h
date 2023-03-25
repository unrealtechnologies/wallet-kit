//
// Created by Ariel Saldana on 3/23/23.
//

#ifndef WALLET_KIT_SPLIT_H
#define WALLET_KIT_SPLIT_H

#include <iostream>
#include <vector>

inline std::vector<std::string> split(const std::string & str, int len)
{
    std::vector<std::string> entries;
    for(std::string::const_iterator it(str.begin()); it != str.end();)
    {
        int nbChar = std::min(len,(int)std::distance(it,str.end()));
        entries.push_back(std::string(it,it+nbChar));
        it=it+nbChar;
    };
    return entries;
}

#endif //WALLET_KIT_SPLIT_H
