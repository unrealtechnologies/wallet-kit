Internally we use two structs to hold data on private keys. The first is the ChainNode which contains both the private
and the public key expressed as ExtendedKeys.

The second is the ExtendedKey which holds information about the type of key (public|private). As well as the key and
chaincode.

In order to minimize data duplication we should try and see where the rest of the data below best fits in order to be
able to 1. derive further keys and 2. be able to serialize the data.

1. version
2. depth
3. fingerprint
4. child number
5. key
6. chaincode
7. key type

Our current API for generating the root ChainNode looks like this:

```c++
std::string mnemonic = "this should be your 12 / 24 word phrase";
auto seed = Bip39::mnemonicToSeed(mnemonic);
auto rootExtendedKey = Bip32::fromSeed(seed);
```

Deriving the public key is then done by calling the derivePublicChildKey method on the rootExtendedKey.

```c++
auto rootPublicKey = Bip32::derivePublicChildKey(*rootExtendedKey);
auto base58EncodedString = rootPublicKey->toBase58();
```

When serializing a key to a base58 encoded string, it's necessary to have information on the version, depth, fingerprint, childNumber, key and chaincode.

| Data Identifier | ChainNode | ExtendedKey |
|-----------------|-----------|-------------|
| Version         |           |             |
| Depth           |           |             |
| FingerPrint     |           |             |
| ChildNumber     |           |             |
| Key             |           |             |
| ChainCode       |           |             |


Would it be fair to create ChainNode which has ChainKeys and ChainContext as parameters
ChainKeys would contain both the public and private key info.
Chain context would contain the version, depth, fingerprint, childNumber, chaincode.

Perhaps we should call a constructor to ChainNode using a private extended key, and then auto generate the 
