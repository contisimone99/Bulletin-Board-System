#include "header/session.h"

class Session {
private:
    std::string sessionId;
    std::map<std::string, std::string> data;

public:
    Session() {
        generateSessionId();
    }

    void setData(const std::string& key, const std::string& value) {
        data[key] = value;
    }

    std::string getData(const std::string& key) {
        if (data.find(key) != data.end()) {
            return data[key];
        } else {
            return "";
        }
    }

    std::string getId() {
        return sessionId;
    }

private:
    void generateSessionId() {
        unsigned char buffer[SHA256_DIGEST_LENGTH];
        RAND_bytes(buffer, SHA256_DIGEST_LENGTH);

        char hexBuffer[SHA256_DIGEST_LENGTH * 2 + 1];
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(&hexBuffer[i * 2], "%02x", buffer[i]);
        }

        sessionId = hexBuffer;
    }

    void get_session_id() {
        
    }
};