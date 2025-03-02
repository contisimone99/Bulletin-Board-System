#include "header/utility.h"

/**
 * @brief Securely frees a buffer by zeroing out its contents and deallocating the memory.
 * 
 * This function takes a pointer to a buffer and its length as parameters. It first fills the buffer with zeros
 * using the `memset` function to ensure that any sensitive data stored in the buffer is overwritten. Then, it
 * deallocates the memory using the `free` function and sets the buffer pointer to `nullptr`.
 * 
 * @param buffer A pointer to the buffer to be freed.
 * @param len The length of the buffer.
 */
void securefree(unsigned char *buffer, int len)
{
    memset(buffer, 0, len);
    free(buffer);
    buffer = nullptr;
}

/**
 * @brief Decodes a Base64 encoded string.
 *
 * This function takes a Base64 encoded string and its length as parameters. It creates a BIO object for reading
 * from the encoded string and a BIO object for Base64 decoding. It then performs the Base64 decoding and returns
 * a pointer to the decoded data. The length of the decoded data is also returned through the `outLength` parameter.
 * 
 * @param encodedData The Base64 encoded string to decode.
 * @param outLength   The length of the decoded data.
 * @return            A pointer to the decoded data.
 */
unsigned char *Base64Decode(const std::string &encodedData, size_t &outLength)
{
    // Create a BIO object for reading from the encoded string
    BIO *bio = BIO_new_mem_buf(encodedData.c_str(), encodedData.length());
    BIO *base64Bio = BIO_new(BIO_f_base64());
    BIO_push(base64Bio, bio);

    // Disable line breaks in the Base64 input
    BIO_set_flags(base64Bio, BIO_FLAGS_BASE64_NO_NL);

    // Determine the size of the decoded data
    size_t maxDecodedLength = encodedData.length() / 4 * 3; // Conservative estimate
    unsigned char *decodedData = new unsigned char[maxDecodedLength];

    // Perform the Base64 decoding
    outLength = BIO_read(base64Bio, decodedData, encodedData.length());

    // Cleanup
    BIO_free_all(base64Bio);

    return decodedData;
}

/**
 * @brief Encodes a buffer into a Base64 string.
 *
 * This function takes a pointer to a buffer and its length as parameters. It creates a BIO object for Base64 encoding
 * and writes the buffer into it. The resulting Base64 string is then returned.
 * 
 * @param buffer A pointer to the buffer to encode.
 * @param length The length of the buffer.
 * @return       The Base64 encoded string.
 */
std::string Base64Encode(const unsigned char* buffer, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    //Ignore newlines
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);  
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    std::string encodedData(bufferPtr->data, bufferPtr->length);
    BUF_MEM_free(bufferPtr);
    return encodedData;
}

void printBufferHex(const unsigned char* buffer, size_t size) {
    std::cout << "Hex:" << std::endl;
    
    for (size_t i = 0; i < size; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(buffer[i]) << " ";
        
        if ((i + 1) % 16 == 0)
            std::cout << std::endl;
    }
    
    std::cout << std::dec << std::endl;
    std::cout<<"Size: "<<size<<std::endl;
}

// Given a username return the path in the filesystem
std::string getPath(std::string username){
    std::string curpath=std::filesystem::current_path();
    std::string path = curpath+"/users/"+username;
    return path;
}


std::string char_to_datatype_display(char datatype) {
    if (datatype == CODES::REGISTER) {
        return "REGISTER";
    } else if (datatype == CODES::LOGIN) {
        return "LOGIN";
    }
    else if (datatype == CODES::HELLO)
    {
        return "HELLO";
    }
    else
    {
        return "unknown";
    }
}


std::string buildStringFromUnsignedChar(unsigned char * buffer, int dimension){
    std::string result(reinterpret_cast<char*>(buffer),dimension);
    return result;
}


