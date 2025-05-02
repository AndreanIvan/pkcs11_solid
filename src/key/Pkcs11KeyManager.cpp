#include <iostream>
#include <cstdlib>

#include "key/Pkcs11KeyManager.hpp"
#include "Config.hpp"

Pkcs11KeyManager::Pkcs11KeyManager(IPkcs11SessionManager* sessionManager) : sessionManager_(sessionManager) {}

// Pkcs11KeyManager::~Pkcs11KeyManager() = default;

void Pkcs11KeyManager::generateKey() {
    // Generate an AES key
    CK_MECHANISM keyGenMech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_BBOOL trueVal = CK_TRUE;

    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_ULONG keySize = Config::AES_KEY_SIZE; // 128, 192, or 256 bits
    
    CK_ATTRIBUTE keyTemplate[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_VALUE_LEN, (void*)&keySize, sizeof(keySize) },
        { CKA_ENCRYPT, &trueVal, sizeof(trueVal) },
        { CKA_DECRYPT, &trueVal, sizeof(trueVal) },
        { CKA_TOKEN, &trueVal, sizeof(trueVal) }
    };

    CK_SESSION_HANDLE session = sessionManager_->getSession();
    CK_FUNCTION_LIST_PTR functions = sessionManager_->getFunctionList();

    CK_RV rv = functions->C_GenerateKey(session, &keyGenMech, keyTemplate, 6, &aesKey_);
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to generate AES key with PKCS#11 library");
    }
    return;
}

void Pkcs11KeyManager::loadKey() {}

CK_OBJECT_HANDLE Pkcs11KeyManager::getKey() const {
    return aesKey_;
}
