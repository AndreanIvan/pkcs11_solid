#pragma once
#include "key/IKeyManager.hpp"
#include "session/IPkcs11SessionManager.hpp"

class Pkcs11KeyManager : public IKeyManager {
public:
    explicit Pkcs11KeyManager(IPkcs11SessionManager* sessionManager);

    void generateKey() override;
    void loadKey() override;
    CK_OBJECT_HANDLE getKey() const override;
    // CK_SESSION_HANDLE getSession() const;

private:
    IPkcs11SessionManager* sessionManager_;
    CK_OBJECT_HANDLE aesKey_;
};
