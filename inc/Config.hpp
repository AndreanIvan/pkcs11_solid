#pragma once
#include <cstddef>
#include <string>

namespace Config {
    inline constexpr const char* PKCS11_LIB_PATH = "/usr/lib/softhsm/libsofthsm2.so";
    inline constexpr const char* USER_PIN = "1234";
    inline constexpr size_t AES_KEY_SIZE = 32; // 256 bits
}
