#include <iostream>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <gtest/gtest.h>

#include "pkcs11.h"
#include "Pkcs11Encryptor.hpp"
#include "Pkcs11Decryptor.hpp"

#include "gtest/gtest.h"

/* Constants and Variables */
const char* PKCS11_LIB_PATH = "/usr/lib/softhsm/libsofthsm2.so";
const char* USER_PIN = "1234";
CK_OBJECT_HANDLE aesKey;
const CK_ULONG AES_KEY_SIZE = 16; // 128-bit
const int BUFFER_SIZE = 256;
const std::string defaultPlaintext = "Hello, my name is Andrean Ivan. Nice to meet you!";

/* Unit tests declaration */
TEST(PositiveCase, EncryptDecrypt) {
    // Test data
    std::string plaintext = defaultPlaintext;
    std::vector<uint8_t> plaintextVec(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> ciphertextVec(BUFFER_SIZE, 0);
    std::vector<uint8_t> decryptedVec(BUFFER_SIZE, 0);

    // Encryptor object
    Pkcs11Encryptor encryptor(PKCS11_LIB_PATH);

    // Encrypt data
    encryptor.login(USER_PIN);
    encryptor.generateKey(AES_KEY_SIZE);
    encryptor.encrypt(plaintextVec, ciphertextVec);
    encryptor.decrypt(ciphertextVec, decryptedVec);

    // Check if decrypted data matches original plaintext
    EXPECT_EQ(plaintext, std::string(decryptedVec.begin(), decryptedVec.end()));
}

TEST(NegativeCase, EncryptWithoutKey) {
    // Test data
    std::string plaintext = defaultPlaintext;
    std::vector<uint8_t> plaintextVec(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> ciphertextVec(BUFFER_SIZE, 0);
    std::vector<uint8_t> decryptedVec(BUFFER_SIZE, 0);

    // Encryptor object
    Pkcs11Encryptor encryptor(PKCS11_LIB_PATH);

    // Encrypt data without generating key
    encryptor.login(USER_PIN);
    CK_RV rv = encryptor.encrypt(plaintextVec, ciphertextVec);
    
    EXPECT_NE(rv, CKR_OK); // Decryption should fail without key
}

TEST(NegativaCase, LoginWithWrongPin) {
    // Test data
    std::string plaintext = defaultPlaintext;
    std::vector<uint8_t> plaintextVec(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> ciphertextVec(BUFFER_SIZE, 0);
    std::vector<uint8_t> decryptedVec(BUFFER_SIZE, 0);

    // Encryptor object
    Pkcs11Encryptor encryptor(PKCS11_LIB_PATH);

    // Encrypt data with wrong PIN
    encryptor.login("wrong_pin");
    try {
        encryptor.generateKey(AES_KEY_SIZE);
        FAIL() << "Expected exception not thrown";
    } catch (const std::exception& e) {
        EXPECT_STREQ(e.what(), "Failed to generate AES key with PKCS#11 library");
    }
}

TEST(NegativeCase, DecryptWithWrongCiphertext) {
    // Test data
    std::string plaintext = defaultPlaintext;
    std::vector<uint8_t> plaintextVec(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> ciphertextVec(BUFFER_SIZE, 0);
    std::vector<uint8_t> decryptedVec(BUFFER_SIZE, 0);

    // Encryptor object
    Pkcs11Encryptor encryptor(PKCS11_LIB_PATH);

    // Encrypt data
    encryptor.login(USER_PIN);
    encryptor.generateKey(AES_KEY_SIZE);
    encryptor.encrypt(plaintextVec, ciphertextVec);

    // Decrypt with wrong ciphertext
    std::vector<uint8_t> wrongCiphertext = {0x00, 0x01, 0x02};
    CK_RV rv = encryptor.decrypt(wrongCiphertext, decryptedVec);

    EXPECT_NE(rv, CKR_OK); // Decryption should fail with wrong ciphertext
}


bool test_encrypt_decrypt_successful(void);
bool test_encrypt_without_key(void);
bool test_login_with_wrong_pin(void);
bool test_decrypt_with_wrong_ciphertext(void);

int main() {
    // Initialize Google Test framework
    ::testing::InitGoogleTest();
    
    // Run all tests
    int result = RUN_ALL_TESTS();

    // Print test results
    std::cout << "Test results: " << result << std::endl;

    return result;
}
