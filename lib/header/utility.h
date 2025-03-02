#ifndef UTILITY_H
#define UTILITY_H

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
//#include <cstdlib>
#include <cstring>
//#include <cstdint>
#include <sys/select.h>
#include <time.h>
//#include <signal.h>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
// #include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
// #include <openssl/bn.h>
#include <openssl/dh.h>

#define BUFFER_SIZE 4096

namespace CODES {
    const char REGISTER = '0';
    const char LOGIN    = '1';
    const char HELLO    = '2';
}

#define DEBUG_ON

#ifdef DEBUG_ON
#define DEBUG_PRINT(x)   \
    printf("[DEBUG]: "); \
    printf x;            \
    printf("\n");        \
    fflush(stdout);
#else
#define DEBUG_PRINT(x)
#endif

void securefree(unsigned char *, int);
unsigned char *Base64Decode(const std::string &, size_t &);
std::string Base64Encode(const unsigned char *, size_t);
void printBufferHex(const unsigned char *, size_t);
std::string getPath(std::string);

template <typename T>
void display_vect(std::vector<T> &);
void print_buf(const std::vector<char> &, const std::string &);
void display_pack(const std::vector<char> &);
std::string char_to_datatype_display(std::string);
std::string buildStringFromUnsignedChar(unsigned char * buffer, int dimension);

#endif