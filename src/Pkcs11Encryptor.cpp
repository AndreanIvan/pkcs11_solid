#include <iostream>
#include <cstdlib> 

#include "Pkcs11Encryptor.hpp"

Pkcs11Encryptor::Pkcs11Encryptor(const char* libraryPath) : Pkcs11Connector(libraryPath) {}

Pkcs11Encryptor::~Pkcs11Encryptor() = default;

CK_RV Pkcs11Encryptor::encrypt(std::vector<uint8_t>& plain, std::vector<uint8_t>& cipher) {
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
    if (plain.empty()) {
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

    CK_ULONG cipherLen = plain.size() + 16; // Padding
    cipher.resize(cipherLen);
    rv = C_Encrypt(session, (uint8_t *)plain.data(), plain.size(), cipher.data(), &cipherLen);
    if (rv != CKR_OK) {
        std::cerr << "C_Encrypt failed: " << std::hex << rv << std::endl;
        return rv;
    }

    // Resize to actual length
    cipher.resize(cipherLen);
    return CKR_OK;
}

CK_RV Pkcs11Encryptor::decrypt(std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain) {
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
    if (cipher.empty()) {
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

    CK_ULONG plainLen = cipher.size() + 16; // Padding
    plain.resize(plainLen);
    rv = C_Decrypt(session, (uint8_t *)cipher.data(), cipher.size(), plain.data(), &plainLen);
    if (rv != CKR_OK) {
        std::cerr << "C_Decrypt failed: " << std::hex << rv << std::endl;
        return rv;
    }

    // Resize to actual length
    plain.resize(plainLen);
    return CKR_OK;
}