#include"client.h"

int Client::sendLoginMsg(std::string sent, unsigned char ** nonce,
                    unsigned char ** dh_uchar, EVP_PKEY ** dh_pub){
    
    // Generate the DH key
    *dh_pub = generate_privk();
    int dh_pub_len = 0;
    *dh_uchar = convertToUnsignedChar(*dh_pub, &dh_pub_len);
    if(dh_pub_len<1){
        printf("Error in converting DH params\n");
        return -1;
    }
    DEBUG_PRINT(("Dh_pub_len is %d",dh_pub_len));
    // Generate the nonce
    *nonce = createNonce();
    if(!*nonce){
        fprintf(stderr, "Error generating the nonces\n");
        return -1;
    }

    // Generate the msg to send: Command/DH/NONCE/username
    string cmd = "NEW";
    int msg_len = sent.size() + cmd.size() + dh_pub_len + NONCELEN +2;
    unsigned char* msg = (unsigned char *)malloc(msg_len);
    if(!msg){
        fprintf(stderr, "Error in allocating memory for the message\n");
        return -1;
    }
    memcpy(msg, (unsigned char *)cmd.c_str(), cmd.size()+1);
    memcpy(msg+COMMAND_SIZE, *dh_uchar, dh_pub_len);
    memcpy(msg+COMMAND_SIZE+DHPARLEN, *nonce, NONCELEN);
    memcpy(msg+COMMAND_SIZE+NONCELEN+dh_pub_len, (unsigned char *)sent.c_str(), sent.size()+1);

    // Send the message and return the socked descriptor
    int sd = sendmsg(msg, msg_len);
    securefree(msg, msg_len);
    return sd;
}
/*
int Client::receiveServerLoginAnswer(int sd,
                                unsigned char** nonce_server,
                                unsigned char** dh_params_server, unsigned char** sharedSecret,
                                EVP_PKEY ** dh_pub, unsigned char * dh_client, unsigned char * nonce_client){

    // receive the login answer
    unsigned char * buffer = (unsigned char *)malloc(BUFFER_LEN);
    int ret = read(sd, buffer, BUFFER_LEN);

    DEBUG_PRINT(("Ret value %d",ret));
    
    // if the bytes read are few it means there is and ERR answer
    if(ret < 8){
        cerr<<"Error in login procedure\n";
        return -1;
    }
    
    // Generate the IV
    unsigned char * IV = (unsigned char*)malloc(IVLEN);
    memcpy(IV,buffer, IVLEN);
    DEBUG_PRINT(("IV %s",Base64Encode(IV,IVLEN).c_str()));
    
    // Get the dh parameters from the server
    unsigned char * plainText_DH = (unsigned char*)malloc(DHPARLEN);
    memcpy(plainText_DH,buffer+IVLEN, DHPARLEN);
    DEBUG_PRINT(("DHServer %s",Base64Encode(plainText_DH,DHPARLEN).c_str()));
    *dh_params_server = plainText_DH;

    // Get the nonce from the server
    unsigned char * plainText_Nonce = (unsigned char*)malloc(NONCELEN);
    memcpy(plainText_Nonce, buffer+IVLEN+DHPARLEN, NONCELEN);
    DEBUG_PRINT(("Nonceserver %s",Base64Encode(plainText_Nonce,NONCELEN).c_str()));
    *nonce_server = plainText_Nonce;
    
    // Get the ciphertext from the received message
    unsigned char * cptxt = (unsigned char *)malloc(ret-IVLEN-DHPARLEN-NONCELEN);
    memcpy(cptxt, buffer+IVLEN+DHPARLEN+NONCELEN, ret-IVLEN-DHPARLEN-NONCELEN);
    securefree(buffer, BUFFER_LEN);
    
    // Convert the dh parameters from unsigned char* to EVP_PKEY and derive the shared secret
    EVP_PKEY * dh_server_pub = convertToEVP_PKEY(plainText_DH, DHPARLEN);
    *sharedSecret = derivateDHSharedSecret(*dh_pub,dh_server_pub, nonce_client, plainText_Nonce);
    EVP_PKEY_free(dh_server_pub);

    // Derive the session key and the HMAC key
    unsigned char * session_key = (unsigned char *)malloc(AES128LEN);
    unsigned char * HMACk = (unsigned char *)malloc(SHA256LEN);
    memcpy(session_key, *sharedSecret,AES128LEN);
    memcpy(HMACk, *sharedSecret+AES128LEN,SHA256LEN);
    this->sessionKey = session_key;
    this->HMACKey = HMACk;
    DEBUG_PRINT(("session key %s", Base64Encode(this->sessionKey, AES128LEN).c_str()));
    DEBUG_PRINT(("HMAC key %s", Base64Encode(this->HMACKey, SHA256LEN).c_str()));
    
    // Get the signed hash message 
    int plaintext_len=0;
    unsigned char * signed_hashed = AESdecrypt(cptxt,ret-IVLEN-DHPARLEN-NONCELEN,this->sessionKey, IV,plaintext_len);
    securefree(cptxt,ret-IVLEN-DHPARLEN-NONCELEN);

    // Generate the buffer to hash
    unsigned char * toHash = (unsigned char *)malloc(2*DHPARLEN+2*NONCELEN+IVLEN);
    memcpy(toHash,plainText_DH,DHPARLEN);
    memcpy(toHash+DHPARLEN,plainText_Nonce,NONCELEN);
    memcpy(toHash+DHPARLEN+NONCELEN,dh_client,DHPARLEN);
    memcpy(toHash+DHPARLEN+NONCELEN+DHPARLEN,nonce_client,NONCELEN);
    memcpy(toHash+DHPARLEN+NONCELEN+DHPARLEN+NONCELEN,IV,IVLEN);
    
    // Free IV since it's no longer necessary
    securefree(IV,IVLEN);

    // Hash the buffer and verity the signature
    unsigned char * hashed = getHash(toHash,2*DHPARLEN+2*NONCELEN+IVLEN,nullptr,EVP_sha256());
    securefree(toHash,2*NONCELEN+2*DHPARLEN+IVLEN);
    if(verify_signature(publicKeyServer,signed_hashed,plaintext_len,hashed,SHA256LEN)<=0){
        securefree(signed_hashed, plaintext_len);
        securefree(hashed,SHA256LEN);
        cerr<<"Failed in verifying signature";
    }
    // Free remaining memory and return 0
    securefree(signed_hashed, plaintext_len);
    securefree(hashed,SHA256LEN);
    return 0;
}


int Client::sendHashCheck(int sd, std::string password, EVP_PKEY* privkey, unsigned char* client_dh,
                    unsigned char * nonce_client, unsigned char* server_dh,
                    unsigned char *nonce_server){

    // Create the text to be signed
    unsigned char * IV = generate_IV();
    unsigned char * to_sign = (unsigned char*)malloc(2*DHPARLEN + 2*NONCELEN + IVLEN + password.size()+1);
    if(to_sign == nullptr){
        securefree(IV, IVLEN);
        cerr<<"Error in malloc of to_sign\n";
        return -1;
    }
    memcpy(to_sign, client_dh, DHPARLEN);
    memcpy(to_sign+DHPARLEN, nonce_client, NONCELEN);
    memcpy(to_sign+DHPARLEN+NONCELEN, server_dh, DHPARLEN);
    memcpy(to_sign+2*DHPARLEN+NONCELEN, nonce_server, NONCELEN);
    memcpy(to_sign+2*DHPARLEN+2*NONCELEN, IV, IVLEN);
    memcpy(to_sign+2*DHPARLEN+2*NONCELEN+IVLEN, (unsigned char*)password.c_str(), password.size()+1);


    // Create the hash for the text
    unsigned char * hash = getHash(to_sign, 2*DHPARLEN + 2*NONCELEN + IVLEN + password.size()+1, nullptr, EVP_sha256());
    securefree(to_sign, 2*DHPARLEN + 2*NONCELEN + IVLEN + password.size()+1);
    if(hash == nullptr){
        securefree(IV, IVLEN);
        cerr<<"Error in generation of hash\n";
        return -1;
    }
    unsigned char * signature = signMsg(privkey, hash, SHA256LEN);
    securefree(hash, SHA256LEN);
    if(signature == nullptr){
        securefree(IV, IVLEN);
        cerr<<"Error in generation of signature\n";
        return -1;
    }
    // Create the cptxt
    unsigned char * to_cptxt = (unsigned char *)malloc(SIGNLEN+ password.size()+1);
    if(to_cptxt == nullptr){
        securefree(IV, IVLEN);
        securefree(signature,SIGNLEN);
        cerr<<"Error in malloc of to_cptxt\n";
        return -1;
    }

    memcpy(to_cptxt, signature, SIGNLEN);
    memcpy(to_cptxt+SIGNLEN, (unsigned char*)password.c_str(), password.size()+1);
    securefree(signature,SIGNLEN);
    
    // Encrypt the plaintext
    int len = 0;
    unsigned char * cptxt = AESencrypt(to_cptxt, SIGNLEN+ password.size()+1, sessionKey, IV, len);
    securefree(to_cptxt, SIGNLEN+ password.size()+1);
    if(cptxt == nullptr){
        securefree(IV, IVLEN);
        cerr<<"Error in generation of cptxt\n";
        return -1;
    }

    // Generate the message to be send, send it and free remaining memory
    unsigned char * msg = (unsigned char*)malloc(IVLEN+len);
    if(msg == nullptr){
        securefree(IV, IVLEN);
        securefree(cptxt, len);
        cerr<<"Error in malloc of msg\n";
        return -1;
    }
    memcpy(msg, IV, IVLEN);
    memcpy(msg+IVLEN, cptxt, len);
    securefree(IV, IVLEN);
    securefree(cptxt, len);
    send(sd, msg, IVLEN+len, 0);
    securefree(msg, IVLEN+len);
    return 1;
}
*/