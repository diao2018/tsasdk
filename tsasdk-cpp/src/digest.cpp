#include "tsasdk/digest.hpp"

namespace tsasdk {

const std::string DigestOid::SHA256 = "2.16.840.1.101.3.4.2.1";
const std::string DigestOid::SHA384 = "2.16.840.1.101.3.4.2.2";
const std::string DigestOid::SHA512 = "2.16.840.1.101.3.4.2.3";
const std::string DigestOid::SM3    = "1.2.156.10197.1.401";

const std::string& DigestOid::getOid(DigestAlgorithm algo) {
    switch (algo) {
        case DigestAlgorithm::SHA256: return SHA256;
        case DigestAlgorithm::SHA384: return SHA384;
        case DigestAlgorithm::SHA512: return SHA512;
        case DigestAlgorithm::SM3:    return SM3;
        default: throw std::invalid_argument("Unsupported algorithm");
    }
}

} // namespace tsasdk
