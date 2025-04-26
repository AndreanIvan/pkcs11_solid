#include <iostream>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>

#include "../lib/pkcs11/pkcs11.h"
#include "../inc/Pkcs11Connector.hpp"

Pkcs11Connector::Pkcs11Connector(const char* libraryPath) {
    loadLibrary(libraryPath);
    initialize();
    openSession();
}

Pkcs11Connector::~Pkcs11Connector() {
    logout();
    closeSession();
    deinitialize();
}

void Pkcs11Connector::loadLibrary(const char* path) {
    // Load the PKCS#11 library
    void* module = dlopen(path, RTLD_NOW);
    if (!module) {
        throw std::runtime_error("Failed to load PKCS#11 library");
    }

    // Get the function list
    CK_C_GetFunctionList getFunctionList = (CK_C_GetFunctionList)dlsym(module, "C_GetFunctionList");
    if (!getFunctionList) {
        throw std::runtime_error("Unable to get function list from PKCS#11 library");
    }

    // Initialize the function list
    CK_RV rv = getFunctionList(&pkcs11);
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to get function list from PKCS#11 library");
    }
}

CK_RV Pkcs11Connector::initialize() {
    // Initialize the PKCS#11 library
    CK_C_INITIALIZE_ARGS initArgs = {nullptr, nullptr, nullptr, nullptr, CKF_OS_LOCKING_OK, nullptr};
    CK_RV rv = pkcs11->C_Initialize(&initArgs);
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to initialize PKCS#11 library");
    }
    return rv;
}

CK_RV Pkcs11Connector::deinitialize() {
    // Deinitialize the PKCS#11 library
    CK_RV rv = pkcs11->C_Finalize(NULL_PTR);
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to deinitialize PKCS#11 library");
    }
    return rv;
}

CK_RV Pkcs11Connector::openSession() {
    // Open a session with the first slot
    CK_SLOT_ID slotList[10];
    CK_ULONG slotCount = 10;
    CK_RV rv = pkcs11->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to get slot list from PKCS#11 library");
    }

    slot = slotList[0];
    rv = pkcs11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to open session with PKCS#11 library");
    }
    return rv;
}

CK_RV Pkcs11Connector::closeSession() {
    // Close the session
    CK_RV rv = pkcs11->C_CloseSession(session);
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to close session with PKCS#11 library");
    }
    return rv;
}

CK_RV Pkcs11Connector::login(const char* pin) {
    // Login to the token
    CK_RV rv = pkcs11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)pin, strlen(pin));
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to login to PKCS#11 token");
    }
    return rv;
}

CK_RV Pkcs11Connector::logout() {
    // Logout from the token
    CK_RV rv = pkcs11->C_Logout(session);
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to logout from PKCS#11 token");
    }
    return rv;
}

CK_RV Pkcs11Connector::generateKey(CK_ULONG keySize) {
    // Generate an AES key
    CK_MECHANISM keyGenMech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE aesKey;
    CK_BBOOL trueVal = CK_TRUE;

    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    
    CK_ATTRIBUTE keyTemplate[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_VALUE_LEN, (void*)&keySize, sizeof(keySize) },
        { CKA_ENCRYPT, &trueVal, sizeof(trueVal) },
        { CKA_DECRYPT, &trueVal, sizeof(trueVal) },
        { CKA_TOKEN, &trueVal, sizeof(trueVal) }
    };

    CK_RV rv = pkcs11->C_GenerateKey(session, &keyGenMech, keyTemplate, 6, &aesKey);
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to generate AES key with PKCS#11 library");
    }
    return rv;
}

CK_OBJECT_HANDLE Pkcs11Connector::getGeneratedKey() const {
    return aesKey;
}
