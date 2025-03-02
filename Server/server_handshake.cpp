#include "server.h"

// check if the user exists 
bool Server::verifyClientExist(string username){
    if(username.empty()){
        return false;
    }
    std::string directorypath = getPath(username);
    DEBUG_PRINT(("Directory path %s", directorypath.c_str()));
    if(!filesystem::is_directory(directorypath)){
        return false;
    }
    return true;
}

// This function handles authentication and login of clients
void Server::authAndLogin(unsigned char * buffer, int len,int sd){
    EVP_PKEY *privateKey=read_privk("server_privKey","server"); //importante fixare la funzione che stampa la chiave privata (RSA...)
    if(!privateKey){
        reportError(sd, -1);
        return;
    }
    unsigned char * nonceClient = (unsigned char *)malloc(NONCELEN);
    unsigned char * dh_params_cl = (unsigned char *)malloc(DHPARLEN);
    unsigned char * username = (unsigned char *)malloc(len-NONCELEN-DHPARLEN);

    memcpy(dh_params_cl, buffer, DHPARLEN);
    memcpy(nonceClient, buffer + DHPARLEN , NONCELEN);
    memcpy(username,buffer+DHPARLEN+NONCELEN,len-NONCELEN-DHPARLEN);

    std::string user = (reinterpret_cast<char*>(username));
    free(username);
    DEBUG_PRINT(("User is %s",user.c_str()));

    // First check: control the existance of the user in the system
    if(!verifyClientExist(user)){
        securefree(dh_params_cl,DHPARLEN); //securefree is a function that free the memory and set the pointer to nullptr
        securefree(nonceClient,NONCELEN);
        EVP_PKEY_free(privateKey);
        reportError(sd, -1);
        return;
    }
    
    // Receives the client parameter and generate the shared secret
    EVP_PKEY* dh_pub_server = generate_privK();       //è qui che va generata DH ahhhhhh
    if(!dh_pub_server){
        securefree(dh_params_cl,DHPARLEN);
        securefree(nonceClient,NONCELEN);
        EVP_PKEY_free(privateKey);
        free(username);
        std::cerr<<"Failed to generate server DH parameter";
        return;
    }
    EVP_PKEY* client_dh_param = convertToEVP_PKEY(dh_params_cl,DHPARLEN);
    if(!client_dh_param){
        EVP_PKEY_free(dh_pub_server);
        securefree(dh_params_cl,DHPARLEN);
        securefree(nonceClient,NONCELEN);
        EVP_PKEY_free(privateKey);
        free(username);
        std::cerr<<"Failed to generate client DH parameter";
        return;
    }
    unsigned char * nonce_server = createNonce();
    unsigned char* computed_shared_secret = derivateDHSharedSecret(dh_pub_server, client_dh_param, nonceClient, nonce_server);
    if(!computed_shared_secret){
        securefree(dh_params_cl,DHPARLEN);
        securefree(nonceClient,NONCELEN);
        free(username);
        securefree(nonce_server,NONCELEN);
        EVP_PKEY_free(client_dh_param);
        EVP_PKEY_free(privateKey);
        reportError(sd,-1);
        return;
    }
    EVP_PKEY_free(client_dh_param);

    // At this point we have both the session key and the MAC key
    unsigned char * sessionKey = (unsigned char *)malloc(AES128LEN);
    unsigned char * HMACKey = (unsigned char *)malloc(SHA256LEN);

    memcpy(sessionKey,computed_shared_secret,AES128LEN);
    memcpy(HMACKey,computed_shared_secret+AES128LEN,SHA256LEN);
    DEBUG_PRINT(("Session key: %s",Base64Encode(sessionKey,AES128LEN).c_str()));
    DEBUG_PRINT(("MAC key: %s",Base64Encode(HMACKey,SHA256LEN).c_str()));
    securefree(computed_shared_secret,AES128LEN+SHA256LEN);


    // Now we need to respond to client with 1)server parameter, 2)nonce of the server 3)encrypted signature of client and server parameters
    int dh_pub_len = 0;
    unsigned char* dh_uchar_server = convertToUnsignedChar(dh_pub_server, &dh_pub_len);
    if(!dh_uchar_server){
        securefree(dh_params_cl,DHPARLEN);
        securefree(nonceClient,NONCELEN);
        free(username);
        securefree(sessionKey,AES128LEN);
        securefree(HMACKey,SHA256LEN);
        EVP_PKEY_free(dh_pub_server);
        EVP_PKEY_free(privateKey);
        reportError(sd,-1);
        return;
    }
    EVP_PKEY_free(dh_pub_server);
    
    unsigned char * plainText = (unsigned char*)malloc(DHPARLEN+NONCELEN); // plaintext contains DH parameter and nonce of ther server
    memcpy(plainText, dh_uchar_server,  DHPARLEN);
    memcpy(plainText+DHPARLEN, nonce_server, NONCELEN);
    securefree(dh_uchar_server,DHPARLEN);
    securefree(nonce_server,NONCELEN);

    unsigned char * IV = generate_IV(); // it is used for encryption of the signature
    if(!IV){
        securefree(dh_params_cl,DHPARLEN);
        securefree(nonceClient,NONCELEN);
        free(username);
        securefree(plainText,DHPARLEN+NONCELEN);
        securefree(sessionKey,AES128LEN);
        securefree(HMACKey,SHA256LEN);
        EVP_PKEY_free(privateKey);
        reportError(sd,-1);
        return;
    }

    // We need to calculate the hash to sign 
    unsigned char * to_sign = (unsigned char *)malloc(2*DHPARLEN + 2*NONCELEN + IVLEN);
    memcpy(to_sign, plainText, DHPARLEN+NONCELEN); // DH and nonce server
    memcpy(to_sign+DHPARLEN+NONCELEN, dh_params_cl, DHPARLEN);
    memcpy(to_sign +2*DHPARLEN+NONCELEN, nonceClient, NONCELEN);
    memcpy(to_sign+2*DHPARLEN+2*NONCELEN, IV, IVLEN); // check for integrity of IV

    unsigned char * signedHash = getHash(to_sign, 2*DHPARLEN + 2*NONCELEN+IVLEN, nullptr, EVP_sha256());
    if(!signedHash){
        securefree(dh_params_cl,DHPARLEN);
        securefree(nonceClient,NONCELEN);
        securefree(sessionKey,AES128LEN);
        securefree(HMACKey,SHA256LEN);
        EVP_PKEY_free(privateKey);
        securefree(to_sign,2*DHPARLEN + 2*NONCELEN + IVLEN);
        reportError(sd,-1);
        return;
    }
    securefree(to_sign,2*DHPARLEN + 2*NONCELEN + IVLEN);

    // We need to calculate the hash to digitally sign it
    unsigned char * signature = signMsg(privateKey, signedHash, SHA256LEN);
    if(!signature){
        cerr<<"Failed to sign message"<<endl;
        securefree(dh_params_cl,DHPARLEN);
        securefree(nonceClient,NONCELEN);
        EVP_PKEY_free(privateKey);
        securefree(sessionKey,AES128LEN);
        securefree(HMACKey,SHA256LEN);
        reportError(sd,-1);
        return;
    }
    securefree(signedHash,SHA256LEN);

    // We encrypt the signature
    int cptxt_len = 0;
    unsigned char * cptxt = AESencrypt(signature, SIGNLEN, sessionKey, IV, cptxt_len);
    if(!cptxt){
        cerr<<"Failed to encrypt"<<endl;
        securefree(dh_params_cl,DHPARLEN);
        securefree(nonceClient,NONCELEN);
        securefree(sessionKey,AES128LEN);
        securefree(HMACKey,SHA256LEN);
        EVP_PKEY_free(privateKey);
        securefree(signature,SIGNLEN);
        reportError(sd,-1);
        return;
    }
    securefree(signature,SIGNLEN);

    //toSend will contain: IV | DH server | nonce Server | E(session_key,digital_signature(H(params)))
    unsigned char * to_send = (unsigned char*)malloc(DHPARLEN+NONCELEN+cptxt_len+IVLEN);
    memcpy(to_send, IV, IVLEN);
    memcpy(to_send+IVLEN, plainText, DHPARLEN+NONCELEN);
    memcpy(to_send+IVLEN+DHPARLEN+NONCELEN, cptxt, cptxt_len);
    securefree(cptxt,cptxt_len);

    DEBUG_PRINT(("Send %d to client",DHPARLEN+NONCELEN+cptxt_len+IVLEN));
    send(sd, to_send, DHPARLEN+NONCELEN+cptxt_len+IVLEN, 0); // send the second message to client

    securefree(IV,IVLEN);
    securefree(to_send,DHPARLEN+NONCELEN+cptxt_len+IVLEN);
    
    unsigned char tmpBuffer[BUFFER_SIZE]; // tmp buffer for receiving client requests
    int byterec=recv(sd, tmpBuffer, BUFFER_SIZE,0); 
    DEBUG_PRINT(("Byte received %d",byterec));
    if(byterec<=4){
        EVP_PKEY_free(privateKey);
        securefree(sessionKey,AES128LEN);
        securefree(HMACKey,SHA256LEN);
        securefree(plainText,DHPARLEN+NONCELEN);
        return;
    }
    IV = (unsigned char *)malloc(IVLEN);
    
    memcpy(IV,tmpBuffer,IVLEN);
    int plain_len=0;
    
    unsigned char * decrypted = AESdecrypt(
        tmpBuffer+IVLEN,
        byterec-IVLEN,
        sessionKey,
        IV,
        plain_len); 

    if(!decrypted){
        cerr<<"Failed to decrypt ciphertext"<<endl;
        securefree(dh_params_cl,DHPARLEN);
        securefree(nonceClient,NONCELEN);
        securefree(sessionKey,AES128LEN);
        securefree(plainText,DHPARLEN+NONCELEN);
        securefree(IV,IVLEN);
        EVP_PKEY_free(privateKey);
        securefree(HMACKey,SHA256LEN);
        reportError(sd,-1);
        return;
    }

    // check if password is correct 
    unsigned char * password = (unsigned char *)malloc(plain_len-SIGNLEN);
    memcpy(password,decrypted+SIGNLEN,plain_len-SIGNLEN);
    std::string passwordS = buildStringFromUnsignedChar(password,plain_len-SIGNLEN);
    if(passwordS.compare(decryptFile(privateKey,"./server/users/"+user+"/"+"password.txt.enc"))!=0){
        cerr<<"Failed to verify the password of the user"<<endl;
        reportError(sd,sessionKey,HMACKey);
        securefree(dh_params_cl,DHPARLEN);
        securefree(nonceClient,NONCELEN);
        securefree(sessionKey,AES128LEN);
        securefree(HMACKey,SHA256LEN);
        securefree(plainText,DHPARLEN+NONCELEN);
        securefree(password,plain_len-SIGNLEN);
        securefree(IV,IVLEN);
        EVP_PKEY_free(privateKey);
        securefree(decrypted,plain_len);
        return;
    }
    
    EVP_PKEY_free(privateKey);

    // now verify client the client response
    unsigned char * toHash = (unsigned char *)malloc(2*NONCELEN+2*DHPARLEN+IVLEN+plain_len-SIGNLEN);
    memcpy(toHash,dh_params_cl,DHPARLEN);
    memcpy(toHash+DHPARLEN,nonceClient,NONCELEN);
    memcpy(toHash+DHPARLEN+NONCELEN,plainText,DHPARLEN+NONCELEN);
    memcpy(toHash+DHPARLEN+NONCELEN+DHPARLEN+NONCELEN,IV,IVLEN);
    memcpy(toHash+DHPARLEN+NONCELEN+DHPARLEN+NONCELEN+IVLEN,password,plain_len-SIGNLEN);

    securefree(password,plain_len-SIGNLEN);
    securefree(dh_params_cl,DHPARLEN);
    securefree(nonceClient,NONCELEN);
    securefree(plainText,DHPARLEN+NONCELEN);
    securefree(IV,IVLEN);

    unsigned char * hashed = getHash(toHash,2*DHPARLEN+2*NONCELEN+IVLEN+plain_len-SIGNLEN,nullptr,EVP_sha256());
    if(!hashed){
        cerr<<"Failed to compute hash"<<endl;
        securefree(toHash,2*DHPARLEN+2*NONCELEN+IVLEN+plain_len-SIGNLEN);
        securefree(sessionKey,AES128LEN);
        securefree(HMACKey,SHA256LEN);
        securefree(decrypted,plain_len);
        reportError(sd,-1);
        return;
    }

    // check if the signature is valid and contains same information 
    EVP_PKEY * userPublicKey = readPublicKey("./server/users/"+user+"/"+user+"_rsa_pubkey.pem");
    if(verify_signature(userPublicKey,decrypted,SIGNLEN,hashed,SHA256LEN)<=0){
        cerr<<"Failed to verify the signature"<<endl;
        EVP_PKEY_free(userPublicKey);
        securefree(toHash,2*DHPARLEN+2*NONCELEN+IVLEN+plain_len-SIGNLEN);
        securefree(decrypted,plain_len);
        securefree(sessionKey,AES128LEN);
        securefree(HMACKey,SHA256LEN);
    }
    securefree(toHash,2*DHPARLEN+2*NONCELEN+IVLEN+plain_len-SIGNLEN);
    EVP_PKEY_free(userPublicKey);
    securefree(hashed,SHA256LEN);
    securefree(decrypted,plain_len);
    memset(tmpBuffer,0,BUFFER_SIZE);
    
    // at this point client is authenticated 

    id_clients++;
    DEBUG_PRINT(("Current id %d",id_clients));
    LoggedUser newUser; 
    newUser.username=user;
    newUser.session_key=sessionKey;
    newUser.HMAC_key=HMACKey;
    newUser.session_key_generation_ts=time(0); // for correct handling of TTL of the session_key
    newUser.id=id_clients;
    newUser.operation_counter_client=0; // for preventing replay attacks
    newUser.operation_counter_server=0;
    newUser.logged=true;
    user_logged.push_back(newUser);
    std::string res = "OKLOG " + to_string(int(id_clients)); // respond to client with its id
    unsigned char* IV_final = nullptr;
    unsigned char* to_hashed_final = nullptr;
    unsigned char* HMAC = nullptr;
    unsigned char* to_enc_final = nullptr;
    int msg_len = 0;
    int enc_len = 0;
    unsigned char * msg_final = createCiphertext(res, id_clients, sessionKey,
                        &IV_final, &to_hashed_final, &HMAC, HMACKey, &to_enc_final, &msg_len, &enc_len);
    if(!msg_final){
        securefree(sessionKey,AES128LEN);
        securefree(HMACKey,SHA256LEN);
        reportError(sd,-1);
        return;
    }
    if(IV_final!=nullptr)
        securefree(IV_final, IVLEN);
    if(to_hashed_final!=nullptr)
        securefree(to_hashed_final, IVLEN+enc_len+1);
    if(HMAC!=nullptr)
        securefree(HMAC, SHA256LEN);
    if(to_enc_final != nullptr)
        securefree(to_enc_final, res.length()+1);
    
    send(sd,msg_final,msg_len,0);   
    securefree(msg_final, msg_len);
}
