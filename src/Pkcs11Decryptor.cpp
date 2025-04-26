#include <iostream>
#include <cstdlib> 

#include "../inc/Pkcs11Decryptor.hpp"

Pkcs11Decryptor::Pkcs11Decryptor(const char* libraryPath) : Pkcs11Connector(libraryPath) {}

Pkcs11Decryptor::~Pkcs11Decryptor() = default;

CK_RV Pkcs11Decryptor::decrypt(const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain, CK_OBJECT_HANDLE &aesKeyArg) {
    // Check if the session is open
    if (session == CK_INVALID_HANDLE) {
        std::cerr << "Session is not open." << std::endl;
        return CKR_SESSION_HANDLE_INVALID;
    }

    // Check if the key is generated
    if (aesKeyArg == CK_INVALID_HANDLE) {
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
    CK_RV rv = C_DecryptInit(session, &mechanism, aesKeyArg);
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

    plain.resize(plainLen); // Resize to actual length
    return CKR_OK;
}