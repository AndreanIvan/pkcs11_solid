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

    CK_RV encrypt(const CK_BYTE_PTR plain, CK_ULONG plainLen, CK_BYTE_PTR cipher, CK_ULONG_PTR cipherLen);
    CK_RV decrypt(const CK_BYTE_PTR cipher, CK_ULONG cipherLen, CK_BYTE_PTR plain, CK_ULONG_PTR plainLen);
    
};
