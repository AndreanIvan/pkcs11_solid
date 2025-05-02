# Minimum CMake version required
cmake_minimum_required(VERSION 3.10)

# Project name
project(pkcs11_solid)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set output directory for executables
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/build/bin)

# Set where the header files are located
include_directories(
    /usr/include
    # /usr/local/include
    ${PROJECT_SOURCE_DIR}/inc
    ${PROJECT_SOURCE_DIR}/lib/pkcs11/inc
    ${PROJECT_SOURCE_DIR}/lib/gtest/inc
    ${PROJECT_SOURCE_DIR}/lib/gmock/inc
)

# Add the lib folder
link_directories(${PROJECT_SOURCE_DIR}/lib/pkcs11)

# Find the required libraries
find_library(SOFTHSM2_LIBRARY NAMES softhsm2 PATHS ${PROJECT_SOURCE_DIR}/lib/softhsm2 NO_DEFAULT_PATH)

# Dynamically find all source files for the library
file(GLOB_RECURSE PKCS11_SOLID_LIB_SOURCES
    ${PROJECT_SOURCE_DIR}/src/crypto/*.cpp
    ${PROJECT_SOURCE_DIR}/src/key/*.cpp
    ${PROJECT_SOURCE_DIR}/src/service/*.cpp
    ${PROJECT_SOURCE_DIR}/src/session/*.cpp
)

# Add the source files as a library
add_library(pkcs11_solid_lib STATIC ${PKCS11_SOLID_LIB_SOURCES})

# Create the executable
add_executable(pkcs11_solid main.cpp)
# Link to the PKCS#11 library
target_link_libraries(pkcs11_solid PRIVATE pkcs11_solid_lib ${SOFTHSM2_LIBRARY})

# Unit test executable
add_executable(pkcs11_solid_unit_test test/test_main.cpp)
# Link prebuilt GoogleTest
target_link_libraries(pkcs11_solid_unit_test
    pkcs11_solid_lib
    ${PROJECT_SOURCE_DIR}/lib/gtest/libgtest.a
    ${PROJECT_SOURCE_DIR}/lib/gtest/libgtest_main.a
    ${SOFTHSM2_LIBRARY}
)
