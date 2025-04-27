# PKCS#11 Solid Project

This project demonstrates PKCS#11 encryption and decryption using SoftHSM2 and C++, following SOLID principles. It includes unit tests and a basic encryption/decryption implementation.

## Prerequisites

- **C++17 or later compiler** (e.g., `g++`)
- **CMake** (for build system)
- **SoftHSM2** (for PKCS#11 implementation)

### Install SoftHSM2

On **Linux**:

```bash
sudo apt-get install libsofthsm2-2 libsofthsm2-dev
```

## Setup

1. **Clone the repository:**

   ```bash
   git clone https://github.com/AndreanIvan/pkcs11_solid.git
   cd pkcs11_solid
   ```

2. **Configure SoftHSM2 Token:**

   ```bash
   export SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf
   softhsm2-util --init-token --slot 0 --label "MyToken" --pin 1234 --so-pin 0000
   ```

3. **Build the project:**

   ```bash
   mkdir build
   cd build
   cmake ..
   make
   ```

4. **Run the project:**

   ```bash
   ./pkcs11_solid
   ```
   Please make sure that the user have `sudo` access.

## Capture of the final result

![Result Capture](./result_capture.png)

## Directory Structure

```
.
├── CMakeLists.txt
├── inc/           # Header files
├── lib/           # External libraries
├── src/           # Source files
├── main.cpp       # Application entry point
└── test/          # Unit tests
```

## Troubleshooting

- **C_Initialize failed**: Ensure SoftHSM2 is installed and the `SOFTHSM2_CONF` is set correctly.
- **Missing `pkcs11.h`**: Make sure the PKCS#11 header is available in the include path.

## Improvement

Following things might be improvement for this project:
- More complex unit test
- Make it more modular
