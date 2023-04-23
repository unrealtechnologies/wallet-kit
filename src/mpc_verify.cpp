//
// Created by Ariel Saldana on 4/9/23.
//
#include <botan/tss.h>
#include <botan/pubkey.h>
#include <botan/auto_rng.h>
#include <iostream>
//
//using namespace Botan;
//
//int main()
//{
//    // Generate a random threshold signature group
//    AutoSeeded_RNG rng;
//    uint32_t threshold = 3;
//    std::vector<Public_Key*> public_keys;
//    std::vector<Private_Key*> private_keys;
//    std::tie(public_keys, private_keys) = TSS_Group::create(rng, "BLS381", threshold);
//
//    // Generate a message to be signed
//    std::string message = "Hello, world!";
//
//    // Sign the message using threshold signatures
//    TSS_Signer signer(private_keys, threshold);
//    std::vector<uint8_t> signature = signer.sign_message(rng, reinterpret_cast<const uint8_t*>(message.data()), message.length());
//
//    // Verify the signature using threshold verification
//    TSS_Verifier verifier(public_keys, threshold);
//    bool valid = verifier.verify_message(reinterpret_cast<const uint8_t*>(message.data()), message.length(), signature);
//    if (valid)
//        std::cout << "Signature is valid!\n";
//    else
//        std::cout << "Signature is invalid!\n";
//
//    // Clean up
//    for (Public_Key* public_key : public_keys)
//        delete public_key;
//    for (Private_Key* private_key : private_keys)
//        delete private_key;
//
//    return 0;
//}


