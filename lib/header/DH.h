#ifndef DH_H
#define DH_H

#include "crypto_utility.h"

//EVP_PKEY *generateDHKey();
EVP_PKEY* generate_privK();
std::streamsize getPEMFileLength(const std::string &);
unsigned char* derive_DH_session_secret(EVP_PKEY* , EVP_PKEY* );
void get_pubK_from_privK(EVP_PKEY*, std::string);

#endif 