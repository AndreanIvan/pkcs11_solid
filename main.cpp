#include <iostream>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>

#include "pkcs11.h"
#include "Pkcs11Encryptor.hpp"
#include "Pkcs11Decryptor.hpp"

int main() {
    /* Constants and Variables */
    const char* PKCS11_LIB_PATH = "/usr/lib/softhsm/libsofthsm2.so";
    const char* USER_PIN = "1234";
    CK_OBJECT_HANDLE aesKey;
    const CK_ULONG AES_KEY_SIZE = 16; // 128-bit

    // Data to encrypt and decrypt
    std::string plaintext = "Hello, my name is Andrean Ivan. Nice to meet you!";

    // Convert string to vector of uint8_t for encryption and decryption
    std::vector<uint8_t> plaintextVec(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> ciphertextVec(256, 0);
    std::vector<uint8_t> decryptedVec(256, 0);

    // Print plaintext vector
    std::cout << "Plain text     : " << plaintextVec.data() << std::endl;

    /* Encryption Section */
    // Initialize Library (Load PKCS#11 library, create new session)
    Pkcs11Encryptor encryptor(PKCS11_LIB_PATH);
    
    // Logs in
    encryptor.login(USER_PIN);

    // Generates AES key
    encryptor.generateKey(AES_KEY_SIZE);
    
    // Encrypts and stores encrypted data
    encryptor.encrypt(plaintextVec, ciphertextVec);
    std::cout << "Encrypted text : " << ciphertextVec.data() << std::endl;
    // std::cout << "Encrypted text len : " << ciphertextVec.size() << std::endl;

    // Gets the generated key
    aesKey = encryptor.getGeneratedKey();

    // Decrypts data
    encryptor.decrypt(ciphertextVec, decryptedVec);

    // Prints decrypted data
    std::cout << "Decrypted text : " << decryptedVec.data() << std::endl;
    // std::cout << "Decrypted text len : " << decryptedVec.size() << std::endl;

    // TODO: Create separate function for Decryptor

    // /* Decryption Section */
    // // Initialize Library (Load PKCS#11 library, create new session)
    // Pkcs11Decryptor decryptor(PKCS11_LIB_PATH);

    // // Logs in
    // decryptor.login(USER_PIN);

    // // Decrypts data
    // decryptor.decrypt(ciphertextVec, decryptedVec, aesKey);

    // // Prints decrypted data
    // // decrypted[decLen] = '\0';
    // std::cout << "Decrypted text: " << decrypted << std::endl;
}