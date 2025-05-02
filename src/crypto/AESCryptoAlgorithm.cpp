#include <iostream>
#include <stdexcept>
#include <vector>
#include "pkcs11.h"
#include "crypto/AESCryptoAlgorithm.hpp"

AESCryptoAlgorithm::AESCryptoAlgorithm(IKeyManager* keyManager, IPkcs11SessionManager* sessionManager)
    : keyManager_(keyManager), sessionManager_(sessionManager) {
    if (!keyManager_ || !sessionManager_) {
        throw std::invalid_argument("Key manager or session manager is null.");
    }
}

std::vector<uint8_t> AESCryptoAlgorithm::encrypt(const std::vector<uint8_t>& plaintext) {
    CK_SESSION_HANDLE session = sessionManager_->getSession();
    CK_FUNCTION_LIST_PTR funcs = sessionManager_->getFunctionList();
    CK_OBJECT_HANDLE key = keyManager_->getKey();

    // Encrypt the plaintext using the key manager
    CK_BYTE iv[16] = {0};
    CK_MECHANISM mechanism = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    CK_RV rv = funcs->C_EncryptInit(session, &mechanism, key);
    if (rv != CKR_OK) {
        std::cerr << "C_EncryptInit failed: " << std::hex << rv << std::endl;
        throw std::runtime_error("Failed to initialize encryption.");
    }

    std::vector<uint8_t> ciphertext(plaintext.size() + 16); // Padding
    CK_ULONG cipherLen = plaintext.size() + 16; // Padding
    rv = funcs->C_Encrypt(session, (uint8_t *)plaintext.data(), plaintext.size(), ciphertext.data(), &cipherLen);
    if (rv != CKR_OK) {
        std::cerr << "C_Encrypt failed: " << std::hex << rv << std::endl;
        throw std::runtime_error("Failed to encrypt data.");
    }

    // Resize to actual length
    ciphertext.resize(cipherLen);
    return ciphertext;    
}

std::vector<uint8_t> AESCryptoAlgorithm::decrypt(const std::vector<uint8_t>& ciphertext) {
    CK_SESSION_HANDLE session = sessionManager_->getSession();
    CK_FUNCTION_LIST_PTR funcs = sessionManager_->getFunctionList();
    CK_OBJECT_HANDLE key = keyManager_->getKey();

    // Decrypt the ciphertext using the key manager
    std::vector<uint8_t> plaintext(ciphertext.size());
    CK_BYTE iv[16] = {0};
    CK_MECHANISM mechanism = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    CK_RV rv = funcs->C_DecryptInit(session, &mechanism, key);
    if (rv != CKR_OK) {
        std::cerr << "C_DecryptInit failed: " << std::hex << rv << std::endl;
        throw std::runtime_error("Failed to initialize decryption.");
    }

    CK_ULONG plainLen = ciphertext.size();
    rv = funcs->C_Decrypt(session, (uint8_t *)ciphertext.data(), ciphertext.size(), plaintext.data(), &plainLen);
    if (rv != CKR_OK) {
        std::cerr << "C_Decrypt failed: " << std::hex << rv << std::endl;
        throw std::runtime_error("Failed to decrypt data.");
    }

    // Resize to actual length
    plaintext.resize(plainLen);
    return plaintext;    
}
