#include "header/DH.h"
#include "header/crypto_utility.h"
#include "header/utility.h"

/*EVP_PKEY *generateDHKey()
{

    EVP_PKEY *DH_params = NULL;
    EVP_PKEY *DH_pub_key = NULL;

    DH_params = EVP_PKEY_new();
    if (!DH_params)
    {
        printf("Error in generating DH params\n");
        return NULL;
    }

    DH *default_DH = DH_get_2048_224();
    int ret = EVP_PKEY_set1_DH(DH_params, default_DH);
    if (ret != 1)
    {
        printf("Error in setting the dh params\n");
        EVP_PKEY_free(DH_params);
        return NULL;
    }

    EVP_PKEY_CTX *ctx_DH = EVP_PKEY_CTX_new(DH_params, nullptr);
    if (!ctx_DH)
    {
        printf("Error in setting the public key algorithm context\n");
        EVP_PKEY_free(DH_params);
        EVP_PKEY_CTX_free(ctx_DH);
        return NULL;
    }

    EVP_PKEY_keygen_init(ctx_DH);
    ret = EVP_PKEY_keygen(ctx_DH, &DH_pub_key);
    if (ret != 1)
    {
        printf("Error in generating the key\n");
        EVP_PKEY_free(DH_params);
        EVP_PKEY_CTX_free(ctx_DH);
        return NULL;
    }

    DH_free(default_DH);
    EVP_PKEY_CTX_free(ctx_DH);
    EVP_PKEY_free(DH_params);
    printEVPKey(DH_pub_key);
    return DH_pub_key;
}*/

/**
 * Generates a private key using Diffie-Hellman key exchange algorithm.
 *
 * @return A pointer to the generated private key (EVP_PKEY*), or NULL if an error occurred.
 */
EVP_PKEY *generate_privK()
{
    EVP_PKEY *dh_params;
    dh_params = EVP_PKEY_new();
    if (!dh_params)
    {
        return NULL;
    }
    // the api below returns preallocated (low-level) object conteining DH parameters (public key of 2048 bit and private key of 224 bit )pag 26 manual
    DH *low_level_dh = DH_get_2048_224();
    // load Diffie hellman parameters in dh_params
    if (!EVP_PKEY_set1_DH(dh_params, low_level_dh))
    {
        DH_free(low_level_dh);
        EVP_PKEY_free(dh_params);
        return NULL;
    }
    DH_free(low_level_dh);

    // generation of private/public key pair
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    if (!ctx)
    {
        EVP_PKEY_free(dh_params);
        return NULL;
    }

    EVP_PKEY *dh_privkey = NULL;
    if (!EVP_PKEY_keygen_init(ctx))
    {
        EVP_PKEY_free(dh_params);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (!EVP_PKEY_keygen(ctx, &dh_privkey))
    {
        EVP_PKEY_free(dh_params);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(dh_params);
    return dh_privkey;
}



/**
 * Retrieves the public key from a private key file.
 *
 * @param filename The path to the private key file in PEM format.
 * @return The public key extracted from the private key file, or nullptr if an error occurs.
 */
void get_pubK_from_privK(EVP_PKEY* privkey, std::string filename)
{
    FILE *PEMpubkey = fopen(filename.c_str(), "w+");
    uint32_t tmp = PEM_write_PUBKEY(PEMpubkey,privkey);
    if(tmp != 1){
        std::cerr<<"Error: fail to extract the public key\n";
        fclose(PEMpubkey);
        return;
    }
    fclose(PEMpubkey);
    return;
}

EVP_PKEY *extract_pubkey_from_PEMfile(std::string filename, unsigned char *buffer, uint32_t file_len)
{

    FILE *pubkey_PEM = fopen(filename.c_str(), "w+");
    if (!pubkey_PEM)
    {
        std::cout << "Error: fail to open file of public key\n";
        return NULL;
    }

    // write received public key into a PEM file.
    uint32_t ret = fwrite(buffer, 1, file_len, pubkey_PEM);
    if (ret < file_len)
    {
        std::cout << "Error: fail to write file of public key\n";
        fclose(pubkey_PEM);
        return NULL;
    }

    fseek(pubkey_PEM, 0, SEEK_SET);
    EVP_PKEY *received_pubkey = PEM_read_PUBKEY(pubkey_PEM, NULL, NULL, NULL);
    if (!received_pubkey)
    {
        std::cout << "Error: fail to read public key\n";
        fclose(pubkey_PEM);
        return NULL;
    }
    fclose(pubkey_PEM);
    return received_pubkey;
}

/**
 * @brief Derives the Diffie-Hellman session secret using the provided private key and public key.
 *
 * @param privkey The private key used for the derivation.
 * @param pubkey The public key of the peer.
 * @param secret_len A pointer to the variable that will hold the length of the derived secret.
 * @return unsigned char* A pointer to the derived shared secret, or NULL if an error occurred.
 *
 * This function derives the shared secret between two parties using the Diffie-Hellman key exchange algorithm.
 * It takes the private key and the public key of the peer as input and returns the derived shared secret.
 * The length of the derived secret is stored in the variable pointed to by secret_len.
 *
 * Note: The caller is responsible for freeing the memory allocated for the shared secret.
 */
unsigned char *derive_DH_session_secret(EVP_PKEY *privkey, EVP_PKEY *pubkey, unsigned char *nonce_1, unsigned char *nonce_2)
{

    /* Create the context for the shared secret derivation */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx)
    {
        std::cerr << "Error in allocating the context" << std::endl;
        return NULL;
    }

    unsigned char *sharedSecret = NULL;
    size_t secret_len = 0;

    /* Initialise the shared secret derivation */
    int ret = EVP_PKEY_derive_init(ctx);
    if (ret != 1)
    {
        std::cerr << "Error in initializing context for DH secret derivation" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Provide the peer public key */
    ret = EVP_PKEY_derive_set_peer(ctx, pubkey);
    if (ret != 1)
    {
        std::cerr << "Error in setting the peer\'s public key for Diffie-Hellman secret derivation" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Determine buffer length, by performing a derivation with a NULL buffer */
    ret = EVP_PKEY_derive(ctx, NULL, &secret_len);
    if (ret != 1)
    {
        std::cerr << "Error in deriving the secret length" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Allocate buffer for the shared secret */
    sharedSecret = (unsigned char *)OPENSSL_malloc(secret_len);
    if (!sharedSecret)
    {
        std::cerr << "Failed malloc" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Derive the shared secret */
    ret = EVP_PKEY_derive(ctx, sharedSecret, &secret_len);
    if (ret != 1)
    {
        std::cerr << "Error in deriving the shared secret" << std::endl;
        securefree(sharedSecret, secret_len);
        return NULL;
    }

    DEBUG_PRINT(("Shared secret in base64\n %s\n", Base64Encode(sharedSecret, secret_len).c_str()));

    // Concat the derived share secret and the nonces
    unsigned char *fresh_sharedSecret = (unsigned char *)OPENSSL_malloc(secret_len + 2 * NONCELEN);
    memcpy(fresh_sharedSecret, sharedSecret, secret_len);
    memcpy(fresh_sharedSecret + secret_len, nonce_1, NONCELEN);
    memcpy(fresh_sharedSecret + secret_len + NONCELEN, nonce_2, NONCELEN);
    securefree(sharedSecret, secret_len);

    // hash the share secret and nonces
    unsigned char *secretHashed = getHash(fresh_sharedSecret, secret_len + 2 * NONCELEN, nullptr);
    if (!secretHashed)
    {
        securefree(fresh_sharedSecret, secret_len + 2 * NONCELEN);
        return nullptr;
    }

    securefree(fresh_sharedSecret, secret_len + 2 * NONCELEN);

    /* Clean up */
    EVP_PKEY_CTX_free(ctx);

    return sharedSecret;
}