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
    const char* plaintext = "Hello, PKCS#11!";
    CK_BYTE ciphertext[256] = {0};
    CK_BYTE decrypted[256] = {0};
    
    CK_ULONG ptLen = strlen(plaintext);
    CK_ULONG ctLen = sizeof(ciphertext);
    CK_ULONG decLen = sizeof(decrypted);

    CK_BYTE paddedPlaintext[16] = {0};
    memcpy(paddedPlaintext, plaintext, ptLen);

    // Wrap paddedPlaintext into a vector for encryption
    std::vector<unsigned char> plaintextVec(paddedPlaintext, paddedPlaintext + sizeof(paddedPlaintext));
    std::vector<unsigned char> ciphertextVec(ciphertext, ciphertext + sizeof(ciphertext));
    std::vector<unsigned char> decryptedVec(decrypted, decrypted + sizeof(decrypted));

    /* Encryption Section */
    // Initialize Library (Load PKCS#11 library, create new session)
    Pkcs11Encryptor encryptor(PKCS11_LIB_PATH);
    
    // Logs in
    encryptor.login(USER_PIN);

    // Generates AES key
    encryptor.generateKey(AES_KEY_SIZE);
    
    // Encrypts and stores encrypted data
    encryptor.encrypt(plaintextVec, ciphertextVec);
    
    // Gets the generated key
    aesKey = encryptor.getGeneratedKey();
    
    /* Decryption Section */
    // Initialize Library (Load PKCS#11 library, create new session)
    Pkcs11Decryptor decryptor(PKCS11_LIB_PATH);

    // // Logs in
    // decryptor.login(USER_PIN);

    // // Decrypts data
    // decryptor.decrypt(ciphertextVec, decryptedVec, aesKey);

    // // Prints decrypted data
    // // decrypted[decLen] = '\0';
    // std::cout << "Decrypted text: " << decrypted << std::endl;
}