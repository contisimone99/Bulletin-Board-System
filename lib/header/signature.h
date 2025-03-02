#ifndef SIGNATURE_H
#define SIGNATURE_H

#include "utility.h"

unsigned char *sign_msg(EVP_PKEY *, const unsigned char *, const size_t);
int verify_signature(EVP_PKEY *,
                     const unsigned char *, const size_t,
                     const unsigned char *, const size_t);


#endif