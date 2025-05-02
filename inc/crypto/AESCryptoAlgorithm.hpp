#pragma once
#include "crypto/ICryptoAlgorithm.hpp"
#include "key/IKeyManager.hpp"
#include "session/IPkcs11SessionManager.hpp"

class AESCryptoAlgorithm : public ICryptoAlgorithm {
public:
    explicit AESCryptoAlgorithm(IKeyManager* keyManager, IPkcs11SessionManager* sessionManager);
    ~AESCryptoAlgorithm() override = default;

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) override;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) override;

private:
    IKeyManager* keyManager_;
    IPkcs11SessionManager* sessionManager_;
};
