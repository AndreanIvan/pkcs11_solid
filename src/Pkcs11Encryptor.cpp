#include <iostream>
#include <cstdlib> 

#include "Pkcs11Encryptor.hpp"

Pkcs11Encryptor::Pkcs11Encryptor(const char* libraryPath) : Pkcs11Connector(libraryPath) {}

Pkcs11Encryptor::~Pkcs11Encryptor() = default;

CK_RV Pkcs11Encryptor::encrypt(const std::vector<uint8_t>& plain, std::vector<uint8_t>& cipher) {

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
    CK_MECHANISM mechanism = {CKM_AES_CBC, nullptr, 0};
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

    cipher.resize(cipherLen); // Resize to actual length
    return CKR_OK;
}
