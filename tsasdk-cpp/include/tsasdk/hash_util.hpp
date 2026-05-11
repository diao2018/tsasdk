#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "tsasdk/digest.hpp"

namespace tsasdk {

/**
 * Hash computation utilities using OpenSSL.
 * Supports SHA-256, SHA-384, SHA-512, and SM3.
 */
class HashUtil {
public:
    /**
     * Compute hash of the given data.
     * @param data Pointer to the data.
     * @param len Length of the data.
     * @param algo Digest algorithm.
     * @return Hash digest as byte vector.
     */
    static std::vector<uint8_t> computeHash(const uint8_t* data, size_t len, DigestAlgorithm algo);

    /**
     * Compute hash of a string.
     * @param text The text to hash.
     * @param algo Digest algorithm.
     * @return Hash digest as byte vector.
     */
    static std::vector<uint8_t> computeHash(const std::string& text, DigestAlgorithm algo);

    /**
     * Compute hash of a file.
     * @param filepath Path to the file.
     * @param algo Digest algorithm.
     * @return Hash digest as byte vector.
     */
    static std::vector<uint8_t> computeHashFile(const std::string& filepath, DigestAlgorithm algo);

    /**
     * Get the OpenSSL EVP_MD pointer for the given algorithm.
     */
    static const void* getEvpMd(DigestAlgorithm algo);
};

} // namespace tsasdk
