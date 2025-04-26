#/bin/bash
# This script builds the PKCS#11 example program using g++

g++ pkcs_11_single_file.cpp -o pkcs_11_single_file -ldl -I../lib/pkcs11
