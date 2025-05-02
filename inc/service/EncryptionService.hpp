#pragma once
#include "crypto/ICryptoAlgorithm.hpp"

class EncryptionService {
public:
    explicit EncryptionService(ICryptoAlgorithm* algorithm);

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext);

private:
    ICryptoAlgorithm* algorithm_;
};
