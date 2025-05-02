#pragma once
#include "session/IPkcs11SessionManager.hpp"
#include "Config.hpp"

class Pkcs11SessionManager : public IPkcs11SessionManager {
public:
    Pkcs11SessionManager(const char* libraryPath = Config::PKCS11_LIB_PATH, const char * userPin = Config::USER_PIN);
    ~Pkcs11SessionManager();
    CK_SESSION_HANDLE getSession() override;
    CK_FUNCTION_LIST_PTR getFunctionList() override;

private:
    void loadLibrary(const char* path);
    void unloadLibrary();
    CK_RV initialize();
    CK_RV deinitialize();
    CK_RV openSession();
    CK_RV closeSession();
    CK_RV login(const char* pin);
    CK_RV logout();

private:
    CK_SESSION_HANDLE session_;
    void* moduleHandle_;
    CK_FUNCTION_LIST_PTR functions_;
    const char* libraryPath_;
    const char* userPin_;
};
