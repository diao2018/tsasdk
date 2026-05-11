#include "tsasdk/tsa_client.hpp"
#include "tsasdk/hash_util.hpp"
#include <iostream>
#include <iomanip>

static void printHex(const std::vector<uint8_t>& data) {
    for (uint8_t b : data) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
    }
    std::cout << std::dec << std::endl;
}

int main() {
    try {
        // SHA-256 demo
        std::cout << "--- SHA-256 Demo ---" << std::endl;
        tsasdk::TSAClient client("http://test1.tsa.cn/tsa", "tsademo", "tsademo");

        auto hash = tsasdk::HashUtil::computeHash("hello tsa", tsasdk::DigestAlgorithm::SHA256);
        std::cout << "SHA-256 hash: ";
        printHex(hash);

        auto token = client.timestampHash(hash, tsasdk::DigestAlgorithm::SHA256);
        std::cout << "Token length: " << token.size() << std::endl;

        // SM3 demo
        std::cout << "\n--- SM3 Demo ---" << std::endl;
        auto sm3Hash = tsasdk::HashUtil::computeHash("hello tsa sm3", tsasdk::DigestAlgorithm::SM3);
        std::cout << "SM3 hash: ";
        printHex(sm3Hash);

        auto sm3Token = client.timestampHash(sm3Hash, tsasdk::DigestAlgorithm::SM3);
        std::cout << "SM3 Token length: " << sm3Token.size() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
