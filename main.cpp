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
    const char* plaintext = "Hello, my name is Andrean Ivan. Nice to meet you!";
    CK_BYTE ciphertext[256] = {0};
    CK_BYTE decrypted[256] = {0};
    
    CK_ULONG ptLen = strlen(plaintext);
    CK_ULONG ctLen = sizeof(ciphertext);
    CK_ULONG decLen = sizeof(decrypted);

    CK_BYTE paddedPlaintext[16] = {0};
    memcpy(paddedPlaintext, plaintext, ptLen);
    std::cout << "Plain text     : " << plaintext << std::endl;

    /* Encryption Section */
    // Initialize Library (Load PKCS#11 library, create new session)
    Pkcs11Encryptor encryptor(PKCS11_LIB_PATH);
    
    // Logs in
    encryptor.login(USER_PIN);

    // Generates AES key
    encryptor.generateKey(AES_KEY_SIZE);
    
    // Encrypts and stores encrypted data
    encryptor.encrypt(paddedPlaintext, ptLen, ciphertext, &ctLen);
    std::cout << "Encrypted text : " << ciphertext << std::endl;

    // Gets the generated key
    aesKey = encryptor.getGeneratedKey();

    // Decrypts data
    encryptor.decrypt(ciphertext, ctLen, decrypted, &decLen);

    // Prints decrypted data
    std::cout << "Decrypted text : " << decrypted << std::endl;

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