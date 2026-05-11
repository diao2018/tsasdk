#include "tsasdk/hash_util.hpp"
#include <openssl/evp.h>
#include <openssl/sm3.h>
#include <fstream>
#include <stdexcept>

namespace tsasdk {

const void* HashUtil::getEvpMd(DigestAlgorithm algo) {
    switch (algo) {
        case DigestAlgorithm::SHA256: return EVP_sha256();
        case DigestAlgorithm::SHA384: return EVP_sha384();
        case DigestAlgorithm::SHA512: return EVP_sha512();
        case DigestAlgorithm::SM3:    return EVP_sm3();
        default: throw std::invalid_argument("Unsupported algorithm");
    }
}

std::vector<uint8_t> HashUtil::computeHash(const uint8_t* data, size_t len, DigestAlgorithm algo) {
    const EVP_MD* md = static_cast<const EVP_MD*>(getEvpMd(algo));
    if (!md) {
        throw std::runtime_error("Failed to get EVP_MD for algorithm (requires OpenSSL 1.1.1+ for SM3)");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    std::vector<uint8_t> result(EVP_MD_size(md));

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, result.data(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Hash computation failed");
    }

    EVP_MD_CTX_free(ctx);
    return result;
}

std::vector<uint8_t> HashUtil::computeHash(const std::string& text, DigestAlgorithm algo) {
    return computeHash(reinterpret_cast<const uint8_t*>(text.data()), text.size(), algo);
}

std::vector<uint8_t> HashUtil::computeHashFile(const std::string& filepath, DigestAlgorithm algo) {
    const EVP_MD* md = static_cast<const EVP_MD*>(getEvpMd(algo));
    if (!md) {
        throw std::runtime_error("Failed to get EVP_MD for algorithm");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Cannot open file: " + filepath);
    }

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer))) {
        if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("EVP_DigestUpdate failed");
        }
    }
    if (file.gcount() > 0) {
        if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("EVP_DigestUpdate failed");
        }
    }

    std::vector<uint8_t> result(EVP_MD_size(md));
    if (EVP_DigestFinal_ex(ctx, result.data(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(ctx);
    return result;
}

} // namespace tsasdk
