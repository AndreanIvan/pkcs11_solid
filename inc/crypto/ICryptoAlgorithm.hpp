#pragma once
#include <vector>
#include <cstdint>

class ICryptoAlgorithm {
public:
    virtual ~ICryptoAlgorithm() = default;
    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) = 0;
    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) = 0;
};
