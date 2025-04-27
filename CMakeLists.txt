# Minimum CMake version required
cmake_minimum_required(VERSION 3.10)

# Project name
project(Pkcs11App)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set where the header files are located
include_directories(inc lib/pkcs11)

# Add the lib folder
link_directories(lib/pkcs11)

# Find the required libraries
find_library(SOFTHSM2_LIBRARY NAMES softhsm2 PATHS lib/pkcs11 NO_DEFAULT_PATH)

# Add the source files
set(SOURCE_FILES
    src/Pkcs11Connector.cpp
    src/Pkcs11Decryptor.cpp
    src/Pkcs11Encryptor.cpp
    src/Pkcs11Wrapper.cpp
)

# Create the executable
add_executable(Pkcs11App main.cpp ${SOURCE_FILES})
# Link to the PKCS#11 library
target_link_libraries(Pkcs11App PRIVATE ${SOFTHSM2_LIBRARY})

# Unit test executable
add_executable(Pkcs11App_unit_test tests/test_main.cpp ${SOURCE_FILES})
# Link prebuilt GoogleTest
target_link_libraries(Pkcs11App_unit_test
    ${PROJECT_SOURCE_DIR}/lib/gtest/libgtest.a
    ${PROJECT_SOURCE_DIR}/lib/gtest/libgtest_main.a
    ${SOFTHSM2_LIBRARY}
)
