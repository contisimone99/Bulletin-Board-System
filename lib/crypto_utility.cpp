#include "header/crypto_utility.h"

/**
 * Prints the contents of an EVP_PKEY object.
 *
 * @param pkey The EVP_PKEY object to be printed.
 */
void printEVPKey(EVP_PKEY *pkey, const char* mode)
{
    if (pkey == nullptr)
    {
        std::cout << "EVP_PKEY is nullptr" << std::endl;
        return;
    }

    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == nullptr)
    {
        std::cout << "Failed to create BIO" << std::endl;
        return;
    }
    if(strcmp(mode, "PRIVATE") == 0){
        if(!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL)){
            std::cout << "Failed to write EVP_PKEY to BIO" << std::endl;
            BIO_free_all(bio);
            return;
        }
    }
    else if(strcmp(mode, "PUBLIC")==0){
        if (!PEM_write_bio_PUBKEY(bio, pkey))
        {
            std::cout << "Failed to write EVP_PKEY to BIO" << std::endl;
            BIO_free_all(bio);
            return;
        }
    }
    else{
        std::cout << "Invalid mode" << std::endl;
        BIO_free_all(bio);
        return;
    }
    
    BUF_MEM *bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    DEBUG_PRINT(("EVP_PKEY contents:\n %s", bufferPtr->data));

    BIO_free_all(bio);
}

/**
 * @brief Converts an EVP_PKEY object to an unsigned char buffer.
 *
 * This function takes an EVP_PKEY object and converts it to an unsigned char buffer.
 * The resulting buffer contains the PEM-encoded public key.
 *
 * @param pkey The EVP_PKEY object to convert.
 * @param length A pointer to an integer that will store the length of the resulting buffer.
 * @return The unsigned char buffer containing the PEM-encoded public key, or nullptr if an error occurred.
 */
unsigned char *convertToUnsignedChar(EVP_PKEY *pkey, int *length)
{
    unsigned char *buffer = nullptr;
    BIO *bio = BIO_new(BIO_s_mem());

    if (bio != nullptr)
    {
        if (PEM_write_bio_PUBKEY(bio, pkey) == 1)
        {
            *length = BIO_pending(bio);
            buffer = new unsigned char[*length];
            BIO_read(bio, buffer, *length);
        }

        BIO_free(bio);
    }

    return buffer;
}

/**
 * Writes the given EVP_PKEY public key to a PEM file.
 *
 * @param filename The name of the file to write the key to.
 * @param key The EVP_PKEY public key to write.
 * @return 0 if the key was successfully written to the file, otherwise an error code.
 */
int write_pem_file(std::string filename, EVP_PKEY *key)
{
    FILE *f = fopen(filename.c_str(), "wb");
    if (!f)
    {
        perror("Opening file");
        return EXIT_FAILURE;
    }
    std::cout<<"Writing public key to file"<<std::endl;
    if (!PEM_write_PrivateKey(
        f,                  /* use the FILE* that was opened */
        key,                /* EVP_PKEY structure */
        NULL,         /* default cipher for encrypting the key on disk */
        NULL,               /* passphrase required for decrypting the key on disk */
        0,                  /* length of the passphrase string */
        NULL,               /* callback for requesting a password */
        NULL                /* data to pass to the callback */
    ))
    {
        perror("Error writing private key to file");
        fclose(f);
        return EXIT_FAILURE;
    }
    else{
        printEVPKey(key, "PRIVATE");
    }
    return 0;
}

/**
 * @brief Reads a public or private key from a PEM file.
 *
 * This function reads a public or private key from the specified file path.
 * The file should be in PEM format.
 *
 * @param filename The path to the file containing the key.
 * @param mode The mode to read the key in. Should be either "PRIVATE" or "PUBLIC".
 * @return A pointer to the EVP_PKEY structure representing the key, or nullptr if an error occurred.*/

EVP_PKEY *read_pem_file(std::string filename, const char *mode)
{
    FILE *f = fopen(filename.c_str(), "rb");
    if (!f)
    {
        perror("Opening file");
        return NULL;
    }
    EVP_PKEY *key;
    if (strcmp(mode, "PRIVATE") == 0)
    {
        PEM_read_PrivateKey(f, &key, NULL, NULL); 
        if (!key)
        {
            perror("Error reading private key from file");
            fclose(f);
            return NULL;
        }
    }
    else if (strcmp(mode, "PUBLIC") == 0)
    {
        PEM_read_PUBKEY(f, &key, NULL, NULL);
        if (!key)
        {
            perror("Error reading public key from file");
            fclose(f);
            return NULL;
        }
    }
    else
    {
        perror("Invalid mode");
        fclose(f);
        return NULL;
    }
    fclose(f);
    return key;
}
/*
String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

    String publicKeyPEM = key
      .replace("-----BEGIN PUBLIC KEY-----", "")
      .replaceAll(System.lineSeparator(), "")
      .replace("-----END PUBLIC KEY-----", "");

    byte[] encoded = Base64.decodeBase64(publicKeyPEM);
*/
// Given an unsigned char * of length keyLength, converts it to EVP_PKEY
EVP_PKEY *convertToEVP_PKEY(const unsigned char *keyData, size_t keyLength)
{
    // Load private key data into a BIO
    BIO *bio = BIO_new_mem_buf(keyData, keyLength);

    // Read the private key from the BIO
    EVP_PKEY *key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    printEVPKey(key, "PUBLIC");
    // Clean up the BIO
    BIO_free(bio);

    return key;
}

/**
 * @brief Reads a public key from a file.
 *
 * This function reads a public key from the specified file path.
 * The file should be in PEM format.
 *
 * @param filepath The path to the file containing the public key.
 * @return A pointer to the EVP_PKEY structure representing the public key, or nullptr if an error occurred.
 */

EVP_PKEY *read_pubk(std::string filepath, size_t *file_len)
{
    EVP_PKEY *pubkey = nullptr;
    FILE *file = fopen(filepath.c_str(), "rb");
    DEBUG_PRINT(("Keypath %s", filepath.c_str()));
    if (!file)
    {
        DEBUG_PRINT(("Public key not found!"));
        return pubkey;
    }
    pubkey = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
    if (!pubkey)
    {
        DEBUG_PRINT(("PEM_read_PUBKEY failed!"));
        fclose(file);
        return pubkey;
    }
    fclose(file);
    return pubkey;
}

/**
 * @brief Reads a private key from a file.
 *
 * This function reads a private key from the specified file path and returns an EVP_PKEY pointer.
 *
 * @param filepath The path to the file containing the private key.
 * @param password The password to decrypt the private key (if encrypted).
 * @return An EVP_PKEY pointer to the private key, or nullptr if the key could not be read.
 */
EVP_PKEY *read_privk(std::string filepath, std::string password)
{
    EVP_PKEY *prvkey = nullptr;
    FILE *file = fopen(filepath.c_str(), "r");
    if (!file)
    {
        DEBUG_PRINT(("Private key not found!"));
        return prvkey;
    }
    prvkey = PEM_read_PrivateKey(file, NULL, NULL, const_cast<char *>(password.c_str()));
    if (!prvkey)
    {
        DEBUG_PRINT(("PEM_read_PrivateKey failed!"));
        ERR_print_errors_fp(stderr);
        fclose(file);
        return prvkey;
    }
    fclose(file);
    return prvkey;
}

/**
 * @brief Calculates the hash value of a given message with optional salt.
 *
 * This function uses the EVP digest routines to calculate the hash value of a message.
 * It supports the SHA3-512 algorithm for hashing.
 *
 * @param msg The message to be hashed.
 * @param len The length of the message.
 * @param salt The optional salt to be included in the hash calculation.
 * @return A pointer to the calculated hash value. The caller is responsible for freeing the memory.
 *         Returns nullptr if there was an error during the hash calculation.
 */
unsigned char *getHash(unsigned char *msg, size_t len, unsigned char *salt)
{
    /* The EVP digest routines are a high-level interface to message digests,
    and should be used instead of the digest-specific functions.
    The EVP_MD type is a structure for digest method implementation.
    */

    unsigned char *digest = NULL;
    unsigned int digestlen = 0;
    EVP_MD_CTX *ctx = NULL;

    /* Buffer allocation for the digest */
    digest = (unsigned char *)malloc(EVP_MD_size(SHA_ALGO));
    if (!digest)
    {
        DEBUG_PRINT(("Failed digest malloc!"));
        return nullptr;
    }

    /* [EVP_MD_CTX_new] Allocates and returns a digest context. */
    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        DEBUG_PRINT(("Failed digest context allocation!"));
        return nullptr;
    }

    /* [EVP_DigestInit] Sets up digest context ctx to use a digest type. */
    EVP_DigestInit(ctx, SHA_ALGO);

    if (salt)
        EVP_DigestUpdate(ctx, salt, SALTSIZE);

    DEBUG_PRINT(("Msg size: %lu", len));

    /* [EVP_DigestUpdate] Hashes cnt bytes of data at d into the digest context ctx.
    Can be called several times on the same ctx to hash additional data. */
    EVP_DigestUpdate(ctx, msg, len);

    /* [EVP_DigestFinal] Retrieves the digest value from ctx and places it in md.
    at most EVP_MAX_MD_SIZE bytes will be written. After calling EVP_DigestFinal_ex()
    no more calls to EVP_DigestUpdate() can be made. */
    EVP_DigestFinal(ctx, digest, &digestlen);
    EVP_MD_CTX_free(ctx);

    DEBUG_PRINT(("Digest is:"));
    printBufferHex(digest, digestlen);

    return digest;
}

/**
 * @brief Creates a nonce.
 *
 * This function dynamically allocates memory for a nonce and generates random bytes to fill it.
 *
 * @return A pointer to the generated nonce, or nullptr if the generation fails.
 */
unsigned char *createNonce()
{
    unsigned char *nonce = (unsigned char *)malloc(NONCELEN);
    if (RAND_bytes(nonce, NONCELEN) != 1) // ritorna 1 se successo
    {
        free(nonce);
        printf("RAND_bytes failure\n");
        return nullptr;
    }
    return nonce;
}

/**
 * @brief Verifies the integrity of a hash by comparing the calculated hash with the received hash.
 *
 * @param calculatedHash The calculated hash to be verified.
 * @param receivedHash The received hash to be compared with the calculated hash.
 * @return true if the calculated hash matches the received hash, false otherwise.
 */
bool verifyHash(unsigned char *calculatedHash, unsigned char *receivedHash)
{
    if (CRYPTO_memcmp(calculatedHash, receivedHash, EVP_MD_size(SHA_ALGO)) == 0)
        return true;

    return false;
}

// Generate a random IV used for AES 128
unsigned char *generate_IV()
{
    DEBUG_PRINT(("Iv len %d", IVLEN));
    unsigned char *iv = (unsigned char *)malloc(IVLEN);
    if (RAND_bytes(iv, IVLEN) != 1 || !iv)
    {
        DEBUG_PRINT(("Failed malloc or RAND_bytes!"));
        free(iv);
        return nullptr;
    }
    return iv;
}

/**
 * Generates a one-time password (OTP) using a random number generator.
 * The OTP is a 6-digit number within the range of 100000 to 999999.
 *
 * @return The generated OTP.
 */
int generate_otp()
{
    std::random_device rd;                                 // obtain a random number from hardware
    std::mt19937 eng(rd());                                // seed the generator
    std::uniform_int_distribution<> distr(100000, 999999); // define the range

    return distr(eng);
}


unsigned char * derivateDHSharedSecret(EVP_PKEY *my_key, EVP_PKEY *other_key, unsigned char* nonce_1, unsigned char* nonce_2){

    EVP_PKEY_CTX *ctx_key = EVP_PKEY_CTX_new(my_key, nullptr);
    if (!ctx_key){
        fprintf(stderr, "Error in allocating the context\n");
        return NULL;
    }

    unsigned char *shared_secret = nullptr;
    size_t secret_length = 0;

    int ret = EVP_PKEY_derive_init(ctx_key);
    if(ret != 1){
        fprintf(stderr, "Error in initializing context for DH secret derivation\n");
        EVP_PKEY_CTX_free(ctx_key);
        return NULL;
    }

    ret = EVP_PKEY_derive_set_peer(ctx_key, other_key);
    if(ret != 1){
        fprintf(stderr, "Error in setting the peer\'s public key for Diffie-Hellman secret derivation\n");
        EVP_PKEY_CTX_free(ctx_key);
        return NULL;
    }
    
    ret = EVP_PKEY_derive(ctx_key, nullptr, &secret_length);
    if(ret != 1){
        fprintf(stderr, "Error in deriving the secret length\n");
        EVP_PKEY_CTX_free(ctx_key);
        return NULL;
    }

    shared_secret = (unsigned char *)malloc(secret_length);
    
    if(!shared_secret){
        fprintf(stderr, "Failed malloc\n");
        EVP_PKEY_CTX_free(ctx_key);
        return NULL;
    }

    ret = EVP_PKEY_derive(ctx_key, shared_secret, &secret_length);

    EVP_PKEY_CTX_free(ctx_key);
    if (ret != 1){
        fprintf(stderr, "Error in deriving the shared secret\n");
        securefree(shared_secret,secret_length);
        return NULL;
    }
    DEBUG_PRINT(("Shared secret in base64\n %s\n",Base64Encode(shared_secret, secret_length).c_str()));

    // Concat the derived share secret and the nonces
    unsigned char * fresh_shared_secret = (unsigned char *)malloc(secret_length + 2 * NONCELEN);
    memcpy(fresh_shared_secret, shared_secret, secret_length);
    memcpy(fresh_shared_secret+secret_length, nonce_1, NONCELEN);
    memcpy(fresh_shared_secret+secret_length+NONCELEN, nonce_2, NONCELEN);
    securefree(shared_secret, secret_length);

    // hash the share secret and nonces
    unsigned char *secretHashed = getHash(fresh_shared_secret,secret_length + 2 * NONCELEN,nullptr);
    if(!secretHashed){
        securefree(fresh_shared_secret,secret_length + 2 * NONCELEN);
        return nullptr;
    }
    
    securefree(fresh_shared_secret,secret_length + 2 * NONCELEN);
    return secretHashed;
}

unsigned char * getHMAC(unsigned char *msg, const int msg_len,unsigned char *key,unsigned int &digestlen){
    unsigned char * digest = (unsigned char *)malloc(SHA256LEN);
    if(!digest){
        return nullptr;
    }
    return HMAC(EVP_sha256(),key,SHA256LEN, msg, msg_len,digest, &digestlen);
}