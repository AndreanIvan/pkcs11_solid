#pragma once

#include <vector>
#include <cstdint>
#include "Pkcs11Connector.hpp"

/***
 * @brief PKCS#11 Encryptor class.
 * 
 */
class Pkcs11Encryptor : public Pkcs11Connector {
public:
    Pkcs11Encryptor(const char* libraryPath);
    ~Pkcs11Encryptor() override;

    CK_RV encrypt(std::vector<uint8_t>& plain, std::vector<uint8_t>& cipher);
    CK_RV decrypt(std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain);
    
};
