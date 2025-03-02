#include "header/signature.h"
#include "header/crypto_utility.h"

/**
 * Signs a message using the provided private key and hash.
 *
 * @param privkey The private key used for signing.
 * @param hash The hash of the message to be signed.
 * @param hash_len The length of the hash.
 * @return A pointer to the signature, or NULL if an error occurred.
 */
unsigned char *sign_msg(EVP_PKEY *privkey, const unsigned char *hash, const size_t hash_len)
{
    if (!privkey)
    {
        fprintf(stderr, "Error private key is not existent\n");
        return NULL;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        fprintf(stderr, "Error in allocating digest\n");
        return NULL;
    }

    /* [EVP_SignInit()] initializes a signing context ctx to use the default implementation of digest type. */
    int ret = EVP_SignInit(ctx, SHA_ALGO);
    
    if (ret != 1)
    {
        fprintf(stderr, "Error in initializing the digest\n");
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    /* [EVP_SignUpdate()] hashes cnt bytes of data at d into the signature context ctx. 
    This function can be called several times on the same ctx to include additional data. */
    ret = EVP_SignUpdate(ctx, hash, hash_len);
    if (ret != 1)
    {
        fprintf(stderr, "Error in updating the digest\n");
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    unsigned int signature_len = EVP_PKEY_size(privkey);
    DEBUG_PRINT(("Signature len: %i\n", signature_len));

    unsigned char *signature = (unsigned char *)malloc(signature_len);
    if (!signature)
    {
        fprintf(stderr, "Failed malloc\n");
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    /* [EVP_SignFinal_ex()] signs the data in ctx using the private key and places the signature in sig. 
    The number of bytes of data written (i.e. signature length) will be written at s (at most EVP_PKEY_get_size(privkey) bytes). */
    ret = EVP_SignFinal(ctx, signature, &signature_len, privkey);
    DEBUG_PRINT(("%i\n", signature_len));
    if (ret != 1)
    {
        fprintf(stderr, "Error in signing the digest\n");
        EVP_MD_CTX_free(ctx);
        free(signature);
        return NULL;
    }
    EVP_MD_CTX_free(ctx);
    DEBUG_PRINT(("SIGNATURE\n %s\n", Base64Encode(signature, signature_len).c_str()));
    
    return signature;
}

/**
 * Verifies the signature of a given hash using a public key.
 *
 * @param pubkey The public key used for verification.
 * @param signature The signature to be verified.
 * @param signature_len The length of the signature.
 * @param hash The hash to be verified.
 * @param hash_len The length of the hash.
 * @return Returns 1 if the signature is valid, 0 if the signature is not valid, and -1 if an error occurs.
 */
int verify_signature(EVP_PKEY *pubkey, 
                    const unsigned char *signature, const size_t signature_len, 
                    const unsigned char *hash, const size_t hash_len)
{

    if (!pubkey)
    {
        fprintf(stderr, "Error public key does not exist\n");
        return -1;
    }

    /* [EVP_MD_CTX_new()] Allocates and returns a digest context. */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        fprintf(stderr, "Error in allocating digest\n");
        return -1;
    }
    
    /* [EVP_DigestInit()] sets up digest context ctx to use a digest type from ENGINE impl. ctx. it always uses the default digest implementation.
    type will typically be supplied by a functionsuch as EVP_sha1(). If impl is NULL then the default implementation of digest type is used. */
    int ret = EVP_VerifyInit(ctx, SHA_ALGO);
    if (ret != 1)
    {
        fprintf(stderr, "Error in initializing the digest\n");
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    /*[EVP_DigestUpdate()] hashes cnt bytes of data at d into the digest context ctx. This function can be called several times on the same ctx
    to hash additional data.*/
    ret = EVP_VerifyUpdate(ctx, hash, hash_len);
    if (ret != 1)
    {
        fprintf(stderr, "Error in updating the digest\n");
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    /*[EVP_VerifyFinal()] verifies the data in ctx using the public key pkey and against the siglen bytes at sigbuf.*/
    ret = EVP_VerifyFinal(ctx, signature, signature_len, pubkey);
    if (ret == 0)
    {
        printf("Signature not valid\n");
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    else if (ret == -1)
    {
        fprintf(stderr, "Error in verifing the signature\n");
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return 1;
}