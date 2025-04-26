#pragma once

#include <vector>
#include <cstdint>
#include "Pkcs11Wrapper.hpp"

/***
 * @brief PKCS#11 Connector class.
 * 
 */
class Pkcs11Connector : public IPkcs11Wrapper {
public:
    Pkcs11Connector(const char* libraryPath);
    ~Pkcs11Connector() override;
    CK_RV login(const char* pin) override;
    CK_RV logout() override;
    CK_RV generateKey(CK_ULONG keySize) override;
    CK_OBJECT_HANDLE getGeneratedKey() const override;

private:
    void loadLibrary(const char* path) override;
    CK_RV initialize() override;
    CK_RV deinitialize() override;
    CK_RV openSession() override;
    CK_RV closeSession() override;

protected:
    CK_SLOT_ID slot;    
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE aesKey;
    CK_FUNCTION_LIST_PTR pkcs11;
};
