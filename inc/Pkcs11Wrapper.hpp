#pragma once
#include <vector>
#include <cstdint>
#include <pkcs11.h>

/**
 * @brief Interface for PKCS#11 wrapper.
 * 
 */
class IPkcs11Wrapper {
public:
    virtual ~IPkcs11Wrapper() = default;
    virtual void loadLibrary(const char* path) = 0;
    virtual CK_RV initialize() = 0;
    virtual CK_RV deinitialize() = 0;
    virtual CK_RV openSession() = 0;
    virtual CK_RV closeSession() = 0;
    virtual CK_RV login(const char* pin) = 0;
    virtual CK_RV logout() = 0;
    virtual CK_RV generateKey(CK_ULONG keySize) = 0;
    virtual CK_OBJECT_HANDLE getGeneratedKey() const = 0;
    // virtual CK_RV encrypt(const std::vector<uint8_t>& plain, std::vector<uint8_t>& cipher) = 0;
    // virtual CK_RV decrypt(const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain, CK_OBJECT_HANDLE &aesKeyArg) = 0;
};
