#include <iostream>
// #include <unique_ptr>
#include <memory>
#include "service/EncryptionService.hpp"
#include "crypto/ICryptoAlgorithm.hpp"

EncryptionService::EncryptionService(ICryptoAlgorithm* algorithm) : algorithm_(algorithm) {}

std::vector<uint8_t> EncryptionService::encrypt(const std::vector<uint8_t>& plaintext) {
    return algorithm_->encrypt(plaintext);
}

std::vector<uint8_t> EncryptionService::decrypt(const std::vector<uint8_t>& ciphertext) {
    return algorithm_->decrypt(ciphertext);
}
