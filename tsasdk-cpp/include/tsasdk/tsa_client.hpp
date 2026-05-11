#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "tsasdk/digest.hpp"

namespace tsasdk {

/**
 * RFC 3161 TSA client using libcurl and OpenSSL.
 * Supports SHA-256, SHA-384, SHA-512, and SM3.
 */
class TSAClient {
public:
    /**
     * Construct a TSA client.
     * @param tsaUrl URL of the TSA server.
     * @param username Username for Basic Auth (empty = no auth).
     * @param password Password for Basic Auth.
     * @param timeout HTTP timeout in seconds (default 10).
     * @param defaultAlgo Default digest algorithm.
     */
    TSAClient(const std::string& tsaUrl,
              const std::string& username = "",
              const std::string& password = "",
              int timeout = 10,
              DigestAlgorithm defaultAlgo = DigestAlgorithm::SHA256);

    /**
     * Request a timestamp token for the given data.
     * @param data Pointer to the data.
     * @param len Length of the data.
     * @param algo Override the default digest algorithm.
     * @return Raw timestamp token bytes.
     */
    std::vector<uint8_t> timestampData(const uint8_t* data, size_t len,
                                        DigestAlgorithm algo = DigestAlgorithm::SHA256);

    /**
     * Request a timestamp token for a pre-computed hash.
     * @param hashBytes Pre-computed hash digest.
     * @param algo The algorithm used to compute the hash.
     * @return Raw timestamp token bytes.
     */
    std::vector<uint8_t> timestampHash(const std::vector<uint8_t>& hashBytes,
                                        DigestAlgorithm algo = DigestAlgorithm::SHA256);

    /**
     * Get the TSA URL.
     */
    const std::string& getTsaUrl() const { return tsaUrl_; }

private:
    std::string tsaUrl_;
    std::string username_;
    std::string password_;
    int timeout_;
    DigestAlgorithm defaultAlgo_;

    /**
     * Build RFC 3161 TimeStampReq DER-encoded bytes.
     */
    std::vector<uint8_t> buildTimestampRequest(const std::vector<uint8_t>& hashBytes,
                                                DigestAlgorithm algo, bool certReq = true);

    /**
     * Send timestamp request to TSA server via HTTP.
     */
    std::vector<uint8_t> sendRequest(const std::vector<uint8_t>& requestBytes);
};

} // namespace tsasdk
