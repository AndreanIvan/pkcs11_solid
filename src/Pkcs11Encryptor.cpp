#include <iostream>
#include <cstdlib> 

#include "Pkcs11Encryptor.hpp"

Pkcs11Encryptor::Pkcs11Encryptor(const char* libraryPath) : Pkcs11Connector(libraryPath) {}

Pkcs11Encryptor::~Pkcs11Encryptor() = default;

CK_RV Pkcs11Encryptor::encrypt(const CK_BYTE_PTR plain, CK_ULONG plainLen, CK_BYTE_PTR cipher, CK_ULONG_PTR cipherLen) {

    // Check if the session is open
    if (session == CK_INVALID_HANDLE) {
        std::cerr << "Session is not open." << std::endl;
        return CKR_SESSION_HANDLE_INVALID;
    }

    // Check if the key is generated
    if (aesKey == CK_INVALID_HANDLE) {
        std::cerr << "AES key is not generated." << std::endl;
        return CKR_KEY_HANDLE_INVALID;
    }

    // Check if the plain text is empty
    if (plainLen == 0) {
        std::cerr << "Plain text is empty." << std::endl;
        return CKR_DATA_INVALID;
    }

    // Encrypt the data using PKCS#11
    CK_BYTE iv[16] = {0};
    CK_MECHANISM mechanism = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    CK_RV rv = C_EncryptInit(session, &mechanism, aesKey);
    if (rv != CKR_OK) {
        std::cerr << "C_EncryptInit failed: " << std::hex << rv << std::endl;
        return rv;
    }

    rv = C_Encrypt(session, plain, plainLen, cipher, cipherLen);
    if (rv != CKR_OK) {
        std::cerr << "C_Encrypt failed: " << std::hex << rv << std::endl;
        return rv;
    }

    return CKR_OK;
}

CK_RV Pkcs11Encryptor::decrypt(const CK_BYTE_PTR cipher, CK_ULONG cipherLen, CK_BYTE_PTR plain, CK_ULONG_PTR plainLen) {
    // Check if the session is open
    if (session == CK_INVALID_HANDLE) {
        std::cerr << "Session is not open." << std::endl;
        return CKR_SESSION_HANDLE_INVALID;
    }

    // Check if the key is generated
    if (aesKey == CK_INVALID_HANDLE) {
        std::cerr << "AES key is not generated." << std::endl;
        return CKR_KEY_HANDLE_INVALID;
    }

    // Check if the cipher text is empty
    if (cipherLen == 0) {
        std::cerr << "Cipher text is empty." << std::endl;
        return CKR_DATA_INVALID;
    }

    // Decrypt the data using PKCS#11
    CK_BYTE iv[16] = {0};
    CK_MECHANISM mechanism = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    CK_RV rv = C_DecryptInit(session, &mechanism, aesKey);
    if (rv != CKR_OK) {
        std::cerr << "C_DecryptInit failed: " << std::hex << rv << std::endl;
        return rv;
    }

    rv = C_Decrypt(session, cipher, cipherLen, plain, plainLen);

    if (rv != CKR_OK) {
        std::cerr << "C_Decrypt failed: " << std::hex << rv << std::endl;
        return rv;
    }

    return CKR_OK;
}