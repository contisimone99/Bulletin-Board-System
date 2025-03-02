#ifndef SESSION_H
#define SESSION_H

#include "crypto_utility.h"
#include <string>
#include <map>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

class Session {

private:
    std::string sessionId;
    std::map<std::string, std::string> data;
    void generateSessionId();

public:
    Session(const std::string& id);

    void setData(const std::string& key, const std::string& value);
    std::string getData(const std::string& key);
    std::string getId();
};

#endif // SESSION_H