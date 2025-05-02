#include <iostream>
#include <cstring>
#include <stdexcept>
#include <dlfcn.h>
#include "session/Pkcs11SessionManager.hpp"
#include "utils/Logger.hpp"
#include "Config.hpp"

Pkcs11SessionManager::Pkcs11SessionManager(const char* libraryPath, const char* pin) : session_(CK_INVALID_HANDLE), moduleHandle_(nullptr), functions_(nullptr) {
    // Store the library path and user PIN
    libraryPath_ = libraryPath;
    userPin_ = pin;

    // Load the PKCS#11 library and initialize the session
    loadLibrary(libraryPath_);
    CK_RV rv = initialize();
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to initialize PKCS#11 library");
    }
    rv = openSession();
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to open session with PKCS#11 library");
    }
    rv = login(userPin_);
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to login to PKCS#11 token");
    }
}

Pkcs11SessionManager::~Pkcs11SessionManager() {
    // Logout and close the session
    logout();
    closeSession();
    if (session_ != CK_INVALID_HANDLE) {
        functions_->C_CloseSession(session_);
    }
    if (moduleHandle_) {
        dlclose(moduleHandle_);
    }
    // deinitialize();
    unloadLibrary();
}

CK_SESSION_HANDLE Pkcs11SessionManager::getSession() {
    if (session_ == CK_INVALID_HANDLE) {
        throw std::runtime_error("Session is not initialized or has been closed");
    }
    return session_;
}

CK_FUNCTION_LIST_PTR Pkcs11SessionManager::getFunctionList() {
    if (!functions_) {
        throw std::runtime_error("PKCS#11 function list is not initialized");
    }
    return functions_;
}

void Pkcs11SessionManager::loadLibrary(const char* path) {
    // Load the PKCS#11 library and initialize the session
    moduleHandle_ = dlopen(Config::PKCS11_LIB_PATH, RTLD_NOW);
    if (!moduleHandle_) {
        throw std::runtime_error("Failed to load PKCS#11 library");
    }
    CK_C_GetFunctionList getFunctionList = (CK_C_GetFunctionList)dlsym(moduleHandle_, "C_GetFunctionList");
    if (!getFunctionList) {
        throw std::runtime_error("Unable to get function list from PKCS#11 library");
    }
    CK_RV rv = getFunctionList(&functions_);
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to get function list from PKCS#11 library");
    }
    return;
}

void Pkcs11SessionManager::unloadLibrary() {
    if (moduleHandle_) {
        dlclose(moduleHandle_);
        moduleHandle_ = nullptr;
    }
}

CK_RV Pkcs11SessionManager::initialize() {
    // Initialize the PKCS#11 library
    CK_C_INITIALIZE_ARGS initArgs = {nullptr, nullptr, nullptr, nullptr, CKF_OS_LOCKING_OK, nullptr};
    CK_RV rv = functions_->C_Initialize(&initArgs);
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to initialize PKCS#11 library");
    }
    return rv;
}

CK_RV Pkcs11SessionManager::deinitialize() {
    // Deinitialize the PKCS#11 library
    CK_RV rv = functions_->C_Finalize(nullptr);
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to deinitialize PKCS#11 library");
    }
    return rv;
}

CK_RV Pkcs11SessionManager::openSession() {
    // Open a session with the first slot
    CK_SLOT_ID slotList[10];
    CK_ULONG slotCount = 10;
    CK_RV rv = functions_->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to get slot list from PKCS#11 library");
    }

    rv = functions_->C_OpenSession(slotList[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &session_);
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to open session with PKCS#11 library");
    }
    return rv;
}

CK_RV Pkcs11SessionManager::closeSession() {
    // Close the session
    if (session_ != CK_INVALID_HANDLE) {
        CK_RV rv = functions_->C_CloseSession(session_);
        if (rv != CKR_OK) {
            throw std::runtime_error("Failed to close session with PKCS#11 library");
        }
        session_ = CK_INVALID_HANDLE;
    }
    return CKR_OK;
}

CK_RV Pkcs11SessionManager::login(const char* pin) {
    // Login to the token
    CK_RV rv = functions_->C_Login(session_, CKU_USER, (CK_UTF8CHAR_PTR)pin, strlen(pin));
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to login to PKCS#11 token");
    }
    return rv;
}

CK_RV Pkcs11SessionManager::logout() {
    // Logout from the token
    CK_RV rv = functions_->C_Logout(session_);
    if (rv != CKR_OK) {
        throw std::runtime_error("Failed to logout from PKCS#11 token");
    }
    return rv;
}
