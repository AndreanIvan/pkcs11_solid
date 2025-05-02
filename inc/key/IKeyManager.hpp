#pragma once
#include "pkcs11.h"

class IKeyManager {
public:
    virtual ~IKeyManager() = default;
    virtual void generateKey() = 0;
    virtual void loadKey() = 0;
    virtual CK_OBJECT_HANDLE getKey() const = 0;
};
