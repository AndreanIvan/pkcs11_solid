#pragma once
#include <pkcs11.h>

class IPkcs11SessionManager {
public:
    virtual ~IPkcs11SessionManager() = default;
    virtual CK_SESSION_HANDLE getSession() = 0;
    virtual CK_FUNCTION_LIST_PTR getFunctionList() = 0;
};
