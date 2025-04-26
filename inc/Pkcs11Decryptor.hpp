#pragma once

#include <vector>
#include <cstdint>
#include "Pkcs11Connector.hpp"

/**
 * @brief PKCS#11 Decryptor class.
 * 
 */
class Pkcs11Decryptor : public Pkcs11Connector {
public:
    Pkcs11Decryptor(const char* libraryPath);
    ~Pkcs11Decryptor() override;

    CK_RV decrypt(const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain, CK_OBJECT_HANDLE &aesKeyArg);
};
