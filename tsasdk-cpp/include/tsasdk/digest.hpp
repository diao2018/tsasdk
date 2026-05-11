#pragma once

#include <string>
#include <cstdint>

namespace tsasdk {

/**
 * Supported digest algorithms.
 */
enum class DigestAlgorithm {
    SHA256,
    SHA384,
    SHA512,
    SM3
};

/**
 * OID constants for digest algorithms.
 */
struct DigestOid {
    static const std::string SHA256;
    static const std::string SHA384;
    static const std::string SHA512;
    static const std::string SM3;

    static const std::string& getOid(DigestAlgorithm algo);
};

} // namespace tsasdk
