#ifndef CRYPTO_UTILITY_H
#define CRIPTO_UTILITY_H

#include "utility.h"
#include <random>

#define NONCELEN 8
#define SALTSIZE 8
#define SHA_ALGO EVP_sha3_512()
#define SHA_ALGO_LEN EVP_MD_size(EVP_sha3_512())
#define IVLEN EVP_CIPHER_iv_length(EVP_aes_128_cbc())
#define DHPARLEN 1190
#define SHA256LEN EVP_MD_size(EVP_sha256())
#define AES128LEN EVP_CIPHER_key_length(EVP_aes_128_cbc())

void printEVPKey(EVP_PKEY *pkey, const char *);
int write_pem_file(std::string filename, EVP_PKEY *key);
EVP_PKEY *read_pubk(std::string filepath);
EVP_PKEY *read_privk(std::string filepath, std::string password);

unsigned char *getHash(unsigned char *, size_t, unsigned char *);
bool verifyHash(unsigned char *, unsigned char *);
unsigned char *createNonce();
unsigned char *generate_IV();
unsigned char *convertToUnsignedChar(EVP_PKEY *pkey, int *length);
int generate_otp();
EVP_PKEY* read_pem_file(const std::string, const char*);
unsigned char * derivateDHSharedSecret(EVP_PKEY *, EVP_PKEY *, unsigned char*, unsigned char*);
unsigned char * getHMAC(unsigned char *msg, const int msg_len,unsigned char *key,unsigned int &digestlen);

#endif
