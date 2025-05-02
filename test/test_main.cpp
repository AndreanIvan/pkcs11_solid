#include <iostream>
#include "service/EncryptionService.hpp"
#include "crypto/AESCryptoAlgorithm.hpp"
#include "key/Pkcs11KeyManager.hpp"
#include "session/Pkcs11SessionManager.hpp"
#include "utils/Logger.hpp"
#include "Config.hpp"

#include "gtest/gtest.h"
#include "service/EncryptionService.hpp"

/* Constants and Variables */
const char* PKCS11_LIB_PATH = "/usr/lib/softhsm/libsofthsm2.so";
const char* USER_PIN = "1234";
CK_OBJECT_HANDLE aesKey;
const CK_ULONG AES_KEY_SIZE = 16; // 128-bit
const int BUFFER_SIZE = 256;
const std::string defaultPlaintext = "Hello, my name is Andrean Ivan. Nice to meet you!";

/* Unit tests declaration */
TEST(PositiveCase, EncryptDecrypt) {
    // Initialize PKCS#11 library and session manager
    Pkcs11SessionManager sessionManager;
    Pkcs11KeyManager keyManager(&sessionManager);
    keyManager.generateKey();
    AESCryptoAlgorithm aes(&keyManager, &sessionManager);
    EncryptionService service(&aes);

    // Test data
    std::string plaintext = defaultPlaintext;
    std::vector<uint8_t> plaintextVec(plaintext.begin(), plaintext.end());

    // Encrypt and decrypt data
    auto ciphertextVec = service.encrypt(plaintextVec);
    auto decryptedVec = service.decrypt(ciphertextVec);

    // Assertions
    EXPECT_EQ(plaintextVec.size(), decryptedVec.size()); // Check if sizes match
    EXPECT_EQ(memcmp(plaintextVec.data(), decryptedVec.data(), plaintextVec.size()), 0); // Check if decrypted data matches original plaintext
}

TEST(NegativeCase, EncryptWithoutKey) {
    // Initialize PKCS#11 library and session manager
    Pkcs11SessionManager sessionManager;
    Pkcs11KeyManager keyManager(&sessionManager);
    AESCryptoAlgorithm aes(&keyManager, &sessionManager);
    EncryptionService service(&aes);

    // Test data
    std::string plaintext = defaultPlaintext;
    std::vector<uint8_t> plaintextVec(plaintext.begin(), plaintext.end());

    // Encrypt and decrypt data
    try {
        auto ciphertextVec = service.encrypt(plaintextVec);
        FAIL() << "Expected exception not thrown";
    } catch (const std::exception& e) {
        EXPECT_STREQ(e.what(), "Failed to initialize encryption.");
    }
}

TEST(NegativeCase, DecryptWithWrongCiphertext) {
    // Initialize PKCS#11 library and session manager
    Pkcs11SessionManager sessionManager;
    Pkcs11KeyManager keyManager(&sessionManager);
    keyManager.generateKey();
    AESCryptoAlgorithm aes(&keyManager, &sessionManager);
    EncryptionService service(&aes);

    // Test data
    std::string plaintext = defaultPlaintext;
    std::vector<uint8_t> plaintextVec(plaintext.begin(), plaintext.end());
    auto ciphertextVec = service.encrypt(plaintextVec);

    // Decrypt with wrong ciphertext
    std::vector<uint8_t> wrongCiphertext = {0x00, 0x01, 0x02};
    try {
        auto decryptedVec = service.decrypt(wrongCiphertext);
        FAIL() << "Expected exception not thrown";
    } catch (const std::exception& e) {
        EXPECT_STREQ(e.what(), "Failed to decrypt data.");
    }
}

TEST(NegativeCase, LoginWithWrongPin) {
    // Initialize PKCS#11 library and session manager
    // Use a wrong PIN to test the login failure
    try {
        Pkcs11SessionManager sessionManager(Config::PKCS11_LIB_PATH, "wrong_pin");
        Pkcs11KeyManager keyManager(&sessionManager);
        keyManager.generateKey(); // This should fail
        FAIL() << "Expected exception not thrown";
    } catch (const std::exception& e) {
        EXPECT_STREQ(e.what(), "Failed to login to PKCS#11 token");
    }
}

int main() {
    // Initialize Google Test framework
    ::testing::InitGoogleTest();
    
    // Run all tests
    int result = RUN_ALL_TESTS();

    // Print test results
    if (result == 0) {
        std::cout << "All tests passed!" << std::endl;
    } else {
        std::cout << "Some tests failed!" << std::endl;
    }

    return result;
}
