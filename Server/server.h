#ifndef SERVER_H
#define SERVER_H

#include "../lib/header/utility.h"
#include "../lib/header/crypto_utility.h"
#include "../lib/header/DH.h"
#include "../lib/header/cipher.h"

#define MAX_CLIENTS 10
static unsigned char id_clients = 0;

struct LoggedUser
{
    std::string username;
    int id;
    unsigned char *session_key;
    unsigned char *HMAC_key;
    time_t session_key_generation_ts;
    int operation_counter_client;
    int operation_counter_server;
    uint16_t port;
    bool logged;
};

class Server
{
public:
    Server(const uint16_t port);
    ~Server();
    void run();
    EVP_PKEY *get_privK() { return privKey; };
    EVP_PKEY *get_pubK_client() { return pubKey_client; }
    void set_pubK(EVP_PKEY *pubK)
    {
        this->pubKey = pubK;
    };
    void set_privK(EVP_PKEY *privK)
    {
        this->privKey = privK;
    };
    void set_pubK_client(EVP_PKEY *pubK)
    {
        this->pubKey_client = pubK;
    };

    //roba per l'handshake <3 <3 <3 <3:
    // bool verifyClientExist(std::string username);
    // void authAndLogin(unsigned char * buffer, int len,int sd);
    // void reportError(int sd, int index);

private:
    int port;
    int listener;
    int new_socket;
    int sd;
    int max_sd;
    struct sockaddr_in address;
    struct sockaddr_in cl_addr;
    fd_set master;
    fd_set read_fds;
    int fdmax;
    socklen_t addrlen;
    unsigned char buffer[BUFFER_SIZE];
    EVP_PKEY *pubKey;        // server public key
    EVP_PKEY *privKey;       // server private key
    EVP_PKEY *pubKey_client; // server private key
};

#endif