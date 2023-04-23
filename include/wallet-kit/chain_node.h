//
// Created by Ariel Saldana on 3/29/23.
//

#ifndef WALLET_KIT_LIB_CHAIN_NODE_H
#define WALLET_KIT_LIB_CHAIN_NODE_H

#include <unordered_map>
#include "extended_key.h"
#include "chain_node_context.h"
#include <memory>

/**
 * @brief This struct represents a node in a BIP32/BIP44 key derivation path.
 *
 * A `ChainNode` contains references to the left and right children in the key derivation tree, as well as a map of
 * public/private key pairs indexed by key index. It also contains a shared pointer to a `ChainNodeContext` object,
 * which provides metadata about the key derivation path (e.g. the purpose, coin type, etc.).
 */
struct ChainNode {
    std::unordered_map<uint32_t, std::tuple<std::unique_ptr<ExtendedKey>, std::unique_ptr<ExtendedKey>>> indexes;
    std::shared_ptr<ChainNodeContext> context;
    std::unique_ptr<ChainNode> left; // normal keys
    std::unique_ptr<ChainNode> right; // hardened keys

    /**
     * @brief Default constructor that initializes an empty `ChainNode` object.
     */
    explicit ChainNode();

    /**
     * @brief Derive a private child key at the specified index using the BIP32/BIP44 derivation rules.
     *
     * @param parentKeyIndex The key index of the parent node.
     * @param childKeyIndex The key index of the child node.
     * @param hardened A flag indicating whether the child node should be derived using a hardened derivation path.
     * @return A unique pointer to the derived child key.
     */
    [[nodiscard]] std::unique_ptr<ExtendedKey> derivePrivateChildExtendedKey(
            uint32_t parentKeyIndex,
            uint32_t childKeyIndex,
            bool hardened
    ) const;

    /**
     * @brief Finds the node at the specified path.
     *
     * @param path The path to the node.
     * @return A tuple containing the private and public extended keys of the node.
     * @note This function returns the private and public extended keys of the node at the specified path.
     * @note If the path is not valid or the node does not exist, an exception is thrown.
     * @note The returned extended keys are owned by the caller.
     */
    [[nodiscard]] std::tuple<ExtendedKey, ExtendedKey> findNode(
            const std::string &path
    );

    /**
     * @brief Searches the tree rooted at `currentNode` for the node specified by `pathArr`.
     *
     * This function recursively searches the binary tree rooted at `currentNode` to find the node specified by `pathArr`.
     * If the node is found, it returns a tuple containing the private and public extended keys for that node.
     *
     * @param[in] currentNode A pointer to the root node of the tree to search.
     * @param[in] pathArr The sequence of indices representing the path to the node to be searched.
     * @return A tuple containing the private and public extended keys for the node at the specified path.
     * If the node is not found, both elements of the tuple will be null.
     * @note This function assumes that the path is valid and that the root node is at depth 0.
     */
    [[nodiscard]] std::tuple<ExtendedKey, ExtendedKey> search(
            ChainNode *currentNode,
            const std::vector<uint32_t> &pathArr
    );

    /**
     * @brief Derives the extended private and public keys for a given derivation path.
     *
     * This function takes a string representation of a BIP32 derivation path and derives the corresponding
     * extended private and public keys using the keys stored in the chain node structure.
     *
     * @param path A string representation of the derivation path in the format "m/0'/1/2'/2/100".
     * @return A tuple containing the extended private and public keys.
     * @note The path must start with the BIP32 root key (m), followed by forward slashes (/) and non-negative
     * integers separated by slashes, where a prime (') after a number indicates a hardened derivation.
     */
    [[nodiscard]] std::tuple<ExtendedKey, ExtendedKey> derivePath(const std::string &path);

private:
    /**
     * @brief Inserts a new index into a given chain node with the provided private and public keys.
     * @param node A pointer to the chain node to insert the new index into.
     * @param index The index to insert into the node.
     * @param prvKey A unique pointer to the private key to associate with the new index.
     * @param pubKey A unique pointer to the public key to associate with the new index.
     * @note This function assumes that the caller has already validated the input parameters.
     */
    static void insertIndexIntoNode(ChainNode *node, uint32_t index, std::unique_ptr<ExtendedKey> prvKey,
                                    std::unique_ptr<ExtendedKey> pubKey);
};

#endif //WALLET_KIT_LIB_CHAIN_NODE_H
