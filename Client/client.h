#ifndef CLIENT_H
#define CLIENT_H

#include "../lib/header/utility.h"
#include "../lib/header/crypto_utility.h"

#define STDIN 0
#define OP_LEN 4
#define USER_LEN 30
#define PASSWORD_LEN 30

class Client
{
public:
    Client(const uint16_t serverPort);
    ~Client();
    void run();
    void set_pubKey_server(EVP_PKEY *pubKey_server)
    {
        this->pubKey_server = pubKey_server;
    }
    void set_pubKey(EVP_PKEY *pubKey)
    {
        this->pubKey = pubKey;
    }
    void set_privKey(EVP_PKEY *privKey)
    {
        this->privKey = privKey;
    }
    uint16_t getServerPort()
    {
        return server_port;
    }
    bool isPubServerKeyLoaded();
    std::string register_request();
    int sendLoginMsg(std::string sent, unsigned char ** nonce, unsigned char ** dh_uchar, EVP_PKEY ** dh_pub);
    /*int receiveServerLoginAnswer(int sd, unsigned char** nonce_server, 
                                unsigned char** dh_params_server, unsigned char** sharedSecret,
                                EVP_PKEY ** dh_pub, unsigned char * dh_client, unsigned char * nonce_client);
                                
    int sendHashCheck(int sd, std::string password, EVP_PKEY* privkey, unsigned char* client_dh,
                    unsigned char * nonce_client, unsigned char* server_dh,
                    unsigned char *nonce_server);
    */
private:
    int server_port;
    std::string usr_name;
    int id;
    int counter = 0;
    int counter_server = 0;
    bool logged_in = false;
    sockaddr_in client_address, server_address;
    static const int BACKLOG = 10;
    EVP_PKEY *pubKey;        // client public key
    EVP_PKEY *privKey;       // client private key
    EVP_PKEY *pubKey_server; // server private key

    DH *dh;/*
    unsigned char *sessionKey;
    unsigned char *HMACKey;
    int createConnection();
    void setUsername(std::string usr) { usr_name = usr; }
    int sendmsg(char *send_content);
    int sendmsg(unsigned char *send_content, size_t len);
    int sendLoginMsg(std::string sent, unsigned char **nonce, unsigned char **dh_uchar, EVP_PKEY **dh_pub);
    int receiveServerLoginAnswer(int sd, unsigned char **nonce_server, unsigned char **dh_params_server,
                                 unsigned char **sharedSecret, EVP_PKEY **dh_pub, unsigned char *dh_client,
                                 unsigned char *nonce_client);*/
};

#endif