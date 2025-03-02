#ifndef CIPHER_H
#define CIPHER_H

#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>
#include "utility.h"
#include "crypto_utility.h"

unsigned char * AESencrypt(const unsigned char* buffer, size_t bufferSize, const unsigned char* key, const unsigned char* iv,int& ciphertextlen);
unsigned char * AESdecrypt(const unsigned char* ciphertext, size_t ciphertextSize, const unsigned char* key, const unsigned char* iv,int& plaintextlen);
unsigned char * createCiphertext(std::string msg, int id, unsigned char* sharedSecret,
                                unsigned char** IV, unsigned char** to_hashed,
                                unsigned char** HMAC,unsigned char * HMACKey, unsigned char** to_enc, int* length, int* enc_len);

#endif