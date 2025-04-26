#pragma once

#include <vector>
#include <cstdint>
#include "Pkcs11Connector.hpp"

/**
 * @brief PKCS#11 Decryptor class.
 * 
 */
class Pkcs11KeyGenerator : public Pkcs11Connector {
public:
    Pkcs11KeyGenerator(const char* libraryPath);
    ~Pkcs11KeyGenerator() override;

    CK_RV decrypt(const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain) override;
};
