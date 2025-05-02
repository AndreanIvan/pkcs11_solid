#include <iostream>
#include <cstring>
#include "service/EncryptionService.hpp"
#include "crypto/AESCryptoAlgorithm.hpp"
#include "key/Pkcs11KeyManager.hpp"
#include "session/Pkcs11SessionManager.hpp"
#include "utils/Logger.hpp"

int main() {
    // Print start message
    Logger::info("Starting encryption service");

    // Create session manager
    Pkcs11SessionManager sessionManager;

    // Initialize key manager using the session manager
    Pkcs11KeyManager keyManager(&sessionManager);

    // Generate AES key
    keyManager.generateKey();

    // Create AES algorithm
    AESCryptoAlgorithm aes(&keyManager, &sessionManager);

    // Use the EncryptionService with the AES algorithm
    EncryptionService service(&aes);

    // Example data
    std::string plaintextStr = "Hello, world!";
    std::vector<uint8_t> plaintext(plaintextStr.begin(), plaintextStr.end());

    // Encrypt data
    auto ciphertext = service.encrypt(plaintext);
    Logger::info("Encryption successful");

    // Decrypt data
    auto decrypted = service.decrypt(ciphertext);
    Logger::info("Decryption successful");

    // Print decrypted data
    Logger::info("Decrypted text: " + std::string(decrypted.begin(), decrypted.end()));

    return 0;
}
