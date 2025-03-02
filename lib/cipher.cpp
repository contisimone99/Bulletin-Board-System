#include "header/cipher.h"

unsigned char * AESencrypt(const unsigned char* buffer, size_t bufferSize, const unsigned char* key, const unsigned char* iv,int& ciphertextlen) {
    // Initialize the encryption context
    const int blockLength = EVP_CIPHER_block_size(EVP_aes_128_cbc());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        DEBUG_PRINT(("Error in EVP_CIPHER_CTX_new()!"));
        return nullptr;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv) != 1) {
        DEBUG_PRINT(("Error in EVP_EncryptInit_ex()!"));
        return nullptr;
    }

    // Determine the required output buffer size
    int maxOutputLength = bufferSize + blockLength;
    unsigned char* outputBuffer = (unsigned char *)malloc(maxOutputLength);
    int outputLength = 0;

    // Perform the encryption
    if(EVP_EncryptUpdate(ctx, outputBuffer, &outputLength, buffer, bufferSize)!=1){
        DEBUG_PRINT(("Error in EVP_EncryptUpdate()!"));
        return nullptr;
    }

    // Finalize the encryption
    int finalOutputLength = 0;
    EVP_EncryptFinal_ex(ctx, outputBuffer + outputLength, &finalOutputLength);
    outputLength += finalOutputLength;
    ciphertextlen=outputLength;
    // Clean up the context
    EVP_CIPHER_CTX_free(ctx);

    return outputBuffer;
}

// Decrypt the buffer with AES-128 in CBC mode, return the plaintext and the plaintext length
unsigned char * AESdecrypt(const unsigned char* ciphertext, size_t ciphertextSize, const unsigned char* key, const unsigned char* iv,int& plaintextlen) {
    //const int blockLength = EVP_CIPHER_block_size(EVP_aes_128_cbc());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        DEBUG_PRINT(("Error in EVP_CIPHER_CTX_new()!"));
        return nullptr;
    }

    // Initialize the decryption operation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv) != 1) {
        DEBUG_PRINT(("Error in EVP_DecryptInit_ex()!"));
        return nullptr;
    }

    // Determine the required output buffer size
    int maxOutputLength = ciphertextSize;
    unsigned char* outputBuffer = (unsigned char *)malloc(maxOutputLength);
    int outputLength = 0;

    // Perform the decryption
    if(EVP_DecryptUpdate(ctx, outputBuffer, &outputLength, ciphertext, ciphertextSize)!=1){
        DEBUG_PRINT(("Error in EVP_DecryptUpdate()!"));
        return nullptr;
    }

    // Finalize the decryption
    int finalOutputLength = 0;
    EVP_DecryptFinal_ex(ctx, outputBuffer + outputLength, &finalOutputLength);
    outputLength += finalOutputLength;
    plaintextlen=outputLength;
    // Clean up the context
    EVP_CIPHER_CTX_free(ctx);

    return outputBuffer;
}

unsigned char * createCiphertext(std::string msg, int id, unsigned char* sharedSecret,
                                unsigned char** IV, unsigned char** to_hashed,
                                unsigned char** HMAC,unsigned char * HMACKey, unsigned char** to_enc, int* length, int* enc_len){
    
    int to_enc_len = msg.length() + 1;

    *IV = generate_IV();
    if(!*IV){
        fprintf(stderr, "error in generating the IV\n");
        return nullptr;
    }

    *to_enc = (unsigned char*)malloc(to_enc_len);
    if(!*to_enc){
        fprintf(stderr, "error in generating the buffer for encryption\n");
        return nullptr;
    }
    memcpy(*to_enc, msg.c_str(), msg.length()+1);

    int AES_len = 0;
    unsigned char* cipherText = AESencrypt(*to_enc, to_enc_len, sharedSecret, *IV, AES_len);
    if(!cipherText){
        fprintf(stderr, "error in generating the cipherText\n");
        return nullptr;
    }
    
    int to_hashed_len = IVLEN + AES_len + 1;
    *to_hashed = (unsigned char*)malloc(to_hashed_len);
    if(!*to_hashed){
        fprintf(stderr, "error in generating the buffer of the MAC\n");
        return nullptr;
    }
    *to_hashed[0] = (unsigned char)id;
    memcpy(*to_hashed+1, *IV, IVLEN);
    memcpy(*to_hashed+IVLEN+1, cipherText, AES_len);
    unsigned int digestLen=0;
    *HMAC = getHMAC(*to_hashed,to_hashed_len,HMACKey,digestLen);

    if(!*HMAC){
        fprintf(stderr, "error in generating the MAC\n");
        return nullptr;
    }
    
    unsigned char* concat_msg = (unsigned char*)malloc(1+IVLEN+SHA256LEN+AES_len);
    concat_msg[0]=(unsigned char)id;
    memcpy(concat_msg+1, *IV, IVLEN);
    memcpy(concat_msg+IVLEN+1, *HMAC, SHA256LEN);
    memcpy(concat_msg+SHA256LEN+IVLEN+1, cipherText, AES_len);

    securefree(cipherText, AES_len);
    
    *length = 1+IVLEN+SHA256LEN+AES_len;
    *enc_len = AES_len;
    DEBUG_PRINT(("sended %d ct bytes %d\n", *length, AES_len));
    return concat_msg;

}