#include <iostream>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>

#include "pkcs11.h"
#include "Pkcs11Encryptor.hpp"
#include "Pkcs11Decryptor.hpp"

/* Constants and Variables */
const char* PKCS11_LIB_PATH = "/usr/lib/softhsm/libsofthsm2.so";
const char* USER_PIN = "1234";
CK_OBJECT_HANDLE aesKey;
const CK_ULONG AES_KEY_SIZE = 16; // 128-bit
const int BUFFER_SIZE = 256;
const std::string defaultPlaintext = "Hello, my name is Andrean Ivan. Nice to meet you!";

/* Unit tests declaration */
bool test_encrypt_decrypt_successful(void);
bool test_encrypt_without_key(void);
bool test_login_with_wrong_pin(void);
bool test_decrypt_with_wrong_ciphertext(void);

int main() {
    std::cout << "[ RUN  ] Test encrypt/decrypt successful\n" << (test_encrypt_decrypt_successful() ? "[ PASS ]" : "[ FAIL ]") << std::endl;
    std::cout << "[ RUN  ] Test encrypt without key\n" << (test_encrypt_without_key() ? "[ PASS ]" : "[ FAIL ]") << std::endl;
    std::cout << "[ RUN  ] Test login with wrong pin\n" << (test_login_with_wrong_pin() ? "[ PASS ]" : "[ FAIL ]") << std::endl;
    std::cout << "[ RUN  ] Test decrypt with wrong ciphertext\n" << (test_decrypt_with_wrong_ciphertext() ? "[ PASS ]" : "[ FAIL ]") << std::endl;
    
}

/* Unit tests implementation */
bool test_encrypt_decrypt_successful() {
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
    return (plaintext == std::string(decryptedVec.begin(), decryptedVec.end()));
}

bool test_encrypt_without_key() {
    // Test data
    std::string plaintext = defaultPlaintext;
    std::vector<uint8_t> plaintextVec(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> ciphertextVec(BUFFER_SIZE, 0);
    std::vector<uint8_t> decryptedVec(BUFFER_SIZE, 0);

    // Encryptor object
    Pkcs11Encryptor encryptor(PKCS11_LIB_PATH);

    // Encrypt data
    encryptor.login(USER_PIN);
    CK_RV rv = encryptor.encrypt(plaintextVec, ciphertextVec);
    
    if (rv != CKR_OK) {
        return true; // Decryption should fail without key
    }

    // Should not reach here
    return false;
}

bool test_login_with_wrong_pin() {
    // Test data
    std::string plaintext = defaultPlaintext;
    std::vector<uint8_t> plaintextVec(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> ciphertextVec(BUFFER_SIZE, 0);
    std::vector<uint8_t> decryptedVec(BUFFER_SIZE, 0);

    // Encryptor object
    Pkcs11Encryptor encryptor(PKCS11_LIB_PATH);

    // Encrypt data
    encryptor.login("wrong_pin");
    try {
        encryptor.generateKey(AES_KEY_SIZE);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return true; // Encryption should fail with wrong PIN
    }

    // Should not reach here
    return false;
}

bool test_decrypt_with_wrong_ciphertext() {
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

    if (rv != CKR_OK) {
        return true; // Decryption should fail with wrong ciphertext
    }

    // Should not reach here
    return false;
}
