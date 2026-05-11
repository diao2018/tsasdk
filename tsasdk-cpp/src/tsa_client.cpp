#include "tsasdk/tsa_client.hpp"
#include "tsasdk/hash_util.hpp"
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <curl/curl.h>
#include <chrono>
#include <stdexcept>
#include <cstring>
#include <sstream>

namespace tsasdk {

// --- ASN.1 DER encoding helpers ---

static void appendLength(std::vector<uint8_t>& out, size_t len) {
    if (len < 0x80) {
        out.push_back(static_cast<uint8_t>(len));
    } else {
        std::vector<uint8_t> bytes;
        size_t n = len;
        while (n > 0) {
            bytes.insert(bytes.begin(), static_cast<uint8_t>(n & 0xFF));
            n >>= 8;
        }
        out.push_back(static_cast<uint8_t>(0x80 | bytes.size()));
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
}

static void appendTagAndLength(std::vector<uint8_t>& out, uint8_t tag, const std::vector<uint8_t>& content) {
    out.push_back(tag);
    appendLength(out, content.size());
    out.insert(out.end(), content.begin(), content.end());
}

static void encodeOid(std::vector<uint8_t>& out, const std::string& oidStr) {
    // Parse OID string
    std::vector<int> components;
    std::istringstream iss(oidStr);
    std::string token;
    while (std::getline(iss, token, '.')) {
        components.push_back(std::stoi(token));
    }
    if (components.size() < 2) throw std::invalid_argument("OID must have at least 2 components");

    // Encode OID components
    std::vector<uint8_t> oidBytes;
    oidBytes.push_back(static_cast<uint8_t>(components[0] * 40 + components[1]));

    for (size_t i = 2; i < components.size(); i++) {
        int val = components[i];
        if (val == 0) {
            oidBytes.push_back(0);
        } else {
            std::vector<uint8_t> sub;
            sub.push_back(static_cast<uint8_t>(val & 0x7F));
            val >>= 7;
            while (val > 0) {
                sub.insert(sub.begin(), static_cast<uint8_t>(0x80 | (val & 0x7F)));
                val >>= 7;
            }
            oidBytes.insert(oidBytes.end(), sub.begin(), sub.end());
        }
    }

    appendTagAndLength(out, 0x06, oidBytes);
}

static void encodeNull(std::vector<uint8_t>& out) {
    out.push_back(0x05);
    out.push_back(0x00);
}

static void encodeAlgorithmIdentifier(std::vector<uint8_t>& out, const std::string& oidStr) {
    std::vector<uint8_t> content;
    encodeOid(content, oidStr);
    encodeNull(content);
    appendTagAndLength(out, 0x30, content);
}

static void encodeOctetString(std::vector<uint8_t>& out, const std::vector<uint8_t>& data) {
    appendTagAndLength(out, 0x04, data);
}

static void encodeInteger(std::vector<uint8_t>& out, int64_t value) {
    std::vector<uint8_t> content;
    if (value == 0) {
        content.push_back(0);
    } else {
        bool negate = value < 0;
        uint64_t uval = negate ? static_cast<uint64_t>(-value) : static_cast<uint64_t>(value);
        std::vector<uint8_t> bytes;
        while (uval > 0) {
            bytes.insert(bytes.begin(), static_cast<uint8_t>(uval & 0xFF));
            uval >>= 8;
        }
        if (bytes[0] & 0x80) {
            bytes.insert(bytes.begin(), negate ? 0xFF : 0x00);
        } else if (negate) {
            bytes[0] |= 0x80;
        }
        content = bytes;
    }
    appendTagAndLength(out, 0x02, content);
}

static void encodeBoolean(std::vector<uint8_t>& out, bool value) {
    out.push_back(0x01);
    out.push_back(0x01);
    out.push_back(value ? 0xFF : 0x00);
}

// --- TSAClient implementation ---

TSAClient::TSAClient(const std::string& tsaUrl,
                     const std::string& username,
                     const std::string& password,
                     int timeout,
                     DigestAlgorithm defaultAlgo)
    : tsaUrl_(tsaUrl), username_(username), password_(password),
      timeout_(timeout), defaultAlgo_(defaultAlgo) {}

std::vector<uint8_t> TSAClient::timestampData(const uint8_t* data, size_t len, DigestAlgorithm algo) {
    auto hashBytes = HashUtil::computeHash(data, len, algo);
    return timestampHash(hashBytes, algo);
}

std::vector<uint8_t> TSAClient::timestampHash(const std::vector<uint8_t>& hashBytes, DigestAlgorithm algo) {
    auto requestBytes = buildTimestampRequest(hashBytes, algo);
    return sendRequest(requestBytes);
}

std::vector<uint8_t> TSAClient::buildTimestampRequest(const std::vector<uint8_t>& hashBytes,
                                                       DigestAlgorithm algo, bool certReq) {
    std::string oidStr = DigestOid::getOid(algo);

    // MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
    std::vector<uint8_t> messageImprint;
    encodeAlgorithmIdentifier(messageImprint, oidStr);
    encodeOctetString(messageImprint, hashBytes);
    std::vector<uint8_t> miSeq;
    appendTagAndLength(miSeq, 0x30, messageImprint);

    // TimeStampReq ::= SEQUENCE { version, messageImprint, nonce, certReq }
    std::vector<uint8_t> reqContent;
    // version = 1
    encodeInteger(reqContent, 1);
    // messageImprint
    reqContent.insert(reqContent.end(), miSeq.begin(), miSeq.end());
    // nonce (current time in ms)
    auto now = std::chrono::system_clock::now().time_since_epoch();
    int64_t nonce = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    encodeInteger(reqContent, nonce);
    // certReq
    if (certReq) {
        encodeBoolean(reqContent, true);
    }

    std::vector<uint8_t> request;
    appendTagAndLength(request, 0x30, reqContent);
    return request;
}

// libcurl write callback
static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t totalSize = size * nmemb;
    auto* vec = static_cast<std::vector<uint8_t>*>(userp);
    vec->insert(vec->end(), static_cast<uint8_t*>(contents), static_cast<uint8_t*>(contents) + totalSize);
    return totalSize;
}

std::vector<uint8_t> TSAClient::sendRequest(const std::vector<uint8_t>& requestBytes) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize libcurl");
    }

    std::vector<uint8_t> responseData;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/timestamp-query");
    headers = curl_slist_append(headers, "Content-Transfer-Encoding: binary");

    curl_easy_setopt(curl, CURLOPT_URL, tsaUrl_.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, requestBytes.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(requestBytes.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseData);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, static_cast<long>(timeout_));

    // Basic Auth
    if (!username_.empty()) {
        std::string userpwd = username_ + ":" + password_;
        curl_easy_setopt(curl, CURLOPT_USERPWD, userpwd.c_str());
    }

    CURLcode res = curl_easy_perform(curl);

    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        throw std::runtime_error(std::string("HTTP request failed: ") + curl_easy_strerror(res));
    }
    if (httpCode != 200) {
        throw std::runtime_error("TSA returned HTTP " + std::to_string(httpCode));
    }

    return responseData;
}

} // namespace tsasdk
