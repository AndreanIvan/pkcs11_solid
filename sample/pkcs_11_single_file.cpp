#include <iostream>
#include <cstdlib>
#include <cstring>
#include <pkcs11.h>
#include <dlfcn.h>

#define CHECK_CKR(func, rv) \
    if ((rv) != CKR_OK) { \
        std::cerr << func << " failed: " << std::hex << rv << std::endl; \
        exit(1); \
    }

const char* PKCS11_LIB_PATH = "/usr/lib/softhsm/libsofthsm2.so";
const char* USER_PIN = "1234";
const CK_ULONG AES_KEY_SIZE = 16; // 128-bit

CK_FUNCTION_LIST_PTR pkcs11;

void load_pkcs11_library() {
    void* module = dlopen(PKCS11_LIB_PATH, RTLD_NOW);
    if (!module) {
        std::cerr << "Failed to load PKCS#11 library" << std::endl;
        exit(1);
    }

    CK_C_GetFunctionList getFunctionList = (CK_C_GetFunctionList)dlsym(module, "C_GetFunctionList");
    if (!getFunctionList) {
        std::cerr << "Unable to get function list" << std::endl;
        exit(1);
    }

    CK_RV rv = getFunctionList(&pkcs11);
    CHECK_CKR("C_GetFunctionList", rv);
}

int main() {
    load_pkcs11_library();

    // 1. Initialize the library
    CK_C_INITIALIZE_ARGS initArgs = {nullptr, nullptr, nullptr, nullptr, CKF_OS_LOCKING_OK, nullptr};
    CK_RV rv = pkcs11->C_Initialize(&initArgs);
    // CK_RV rv = pkcs11->C_Initialize(nullptr);
    CHECK_CKR("C_Initialize", rv);

    // 2. Get slot list and open a session
    CK_SLOT_ID slotList[10];
    CK_ULONG slotCount = 10;
    rv = pkcs11->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    CHECK_CKR("C_GetSlotList", rv);

    CK_SLOT_ID slot = slotList[0];
    CK_SESSION_HANDLE session;
    rv = pkcs11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    CHECK_CKR("C_OpenSession", rv);

    // 3. Login to the token
    rv = pkcs11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)USER_PIN, strlen(USER_PIN));
    CHECK_CKR("C_Login", rv);

    // 4. Generate AES key
    CK_MECHANISM keyGenMech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE aesKey;
    CK_BBOOL trueVal = CK_TRUE;

    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    
    CK_ATTRIBUTE keyTemplate[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_VALUE_LEN, (void*)&AES_KEY_SIZE, sizeof(AES_KEY_SIZE) },
        { CKA_ENCRYPT, &trueVal, sizeof(trueVal) },
        { CKA_DECRYPT, &trueVal, sizeof(trueVal) },
        { CKA_TOKEN, &trueVal, sizeof(trueVal) }
    };
    rv = pkcs11->C_GenerateKey(session, &keyGenMech, keyTemplate, 6, &aesKey);
    CHECK_CKR("C_GenerateKey", rv);

    // 5. Encrypt data
    const char* plaintext = "Hello, I'm Andrean!";
    CK_ULONG ptLen = strlen(plaintext);
    CK_BYTE ciphertext[256];
    CK_ULONG ctLen = sizeof(ciphertext);

    CK_BYTE paddedPlaintext[16] = {0};
    memcpy(paddedPlaintext, plaintext, strlen(plaintext));    

    // CK_MECHANISM encMech = { CKM_AES_ECB, NULL_PTR, 0 };
    CK_BYTE iv[16] = {0}; // Normally you'd randomize this
    CK_MECHANISM encMech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    rv = pkcs11->C_EncryptInit(session, &encMech, aesKey);
    CHECK_CKR("C_EncryptInit", rv);
    // rv = pkcs11->C_Encrypt(session, (CK_BYTE_PTR)plaintext, ptLen, ciphertext, &ctLen);
    rv = pkcs11->C_Encrypt(session, paddedPlaintext, 16, ciphertext, &ctLen);
    CHECK_CKR("C_Encrypt", rv);

    std::cout << "Encrypted data: " << ciphertext << std::endl;
    std::cout << "Encrypted data length: " << ctLen << std::endl;

    // 6. Decrypt
    CK_BYTE decrypted[256];
    CK_ULONG decLen = sizeof(decrypted);

    rv = pkcs11->C_DecryptInit(session, &encMech, aesKey);
    CHECK_CKR("C_DecryptInit", rv);
    rv = pkcs11->C_Decrypt(session, ciphertext, ctLen, decrypted, &decLen);
    CHECK_CKR("C_Decrypt", rv);

    decrypted[decLen] = '\0';
    std::cout << "Decrypted text: " << decrypted << std::endl;

    // 7. Cleanup
    pkcs11->C_Logout(session);
    pkcs11->C_CloseSession(session);
    pkcs11->C_Finalize(NULL_PTR);

    return 0;
}
