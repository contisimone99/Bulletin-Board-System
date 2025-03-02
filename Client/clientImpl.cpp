#include "client.h"


Client::Client(const uint16_t serverPort)
{
    // Clear the memory of client_address and server_address structures
    memset(&server_address, 0, sizeof(server_address));

    // Set server address configuration
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(serverPort);
    server_port = serverPort;

    // Print the values for debugging purposes
    DEBUG_PRINT(("communicating with server on %d", server_address.sin_port));
    // get the public key from memory
    // pubKey_server = read_pubk("./server/server_rsa_pubkey.pem");
}

Client::~Client()
{
    EVP_PKEY_free(pubKey_server);
}

void Client::run()
{
    int client_socket;
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        std::cerr << "Failed to create socket\n";
        exit(EXIT_FAILURE);
    }

    if (connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
    {
        std::cerr << "Connection failed at " << inet_ntoa(server_address.sin_addr) << ":" << ntohs(server_address.sin_port) << std::endl;
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    while (true)
    {

        std::string options = "1) Register an account\n2) Login\n";
        int choice;
        while (true)
        {
            char buffer[BUFFER_SIZE];
            memset(buffer, 0, sizeof(buffer));
            std::string req;
            std::cout << options;
            std::cin >> choice;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Ignore remaining characters in the input buffer
            switch (choice)
            {
            case 1:
                std::cout << "Register an account" << std::endl;
                req = register_request();
                for (const auto str : req)
                {
                    std::cout << "Str: " << str;
                    strcat(buffer, &str);
                }
                std::cout << "Buffer: " << buffer << std::endl;
                if (send(client_socket, buffer, strlen(buffer), 0) < 0)
                {
                    std::cerr << "Failed to send message\n";
                    close(client_socket);
                    exit(EXIT_FAILURE);
                }
                memset(buffer, 0, sizeof(buffer));

                break;
            case 2:
                std::cout << "Login" << std::endl;
                break;
            default:
                std::cout << "Invalid option. Please try again." << std::endl;
                break;
            }
        }
        /*
        if (send(client_socket, buffer, strlen(buffer), 0) < 0)
        {
            std::cerr << "Failed to send message\n";
            close(client_socket);
            exit(EXIT_FAILURE);
        }

        if (read(client_socket, buffer, sizeof(buffer)) < 0)
        {
            std::cerr << "Failed to read server reply\n";
            close(client_socket);
            exit(EXIT_FAILURE);
        }
        */
        std::cout << "Server reply: " << std::endl;
    }
    close(client_socket);
}

// Utility function returns true if the public key has been loaded correctly
bool Client::isPubServerKeyLoaded()
{
    if (!pubKey_server)
        return false;
    return true;
}

std::string Client::register_request()
{
    const int EMAILLEN = 25;
    const int PASSWORDLEN = 10;
    const int USERNAMELEN = 20;
    char email[EMAILLEN];
    char password[PASSWORDLEN];
    char password_check[PASSWORDLEN];
    char username[USERNAMELEN];
    memset(email, 0, sizeof(EMAILLEN));
    memset(password, 0, sizeof(PASSWORDLEN));
    memset(username, 0, sizeof(USERNAMELEN));
    
    size_t len_data;
    bool valid = false;

    while (!valid)
    {
        std::cout << "Enter email: ";
        std::cin.getline(email, sizeof(email));
        if (std::cin.fail())
        {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }

        // controlla se la mail contiene almeno un punto e una @
        std::cout << "Checking if the given mail is valid..." << std::endl;
        valid = true; //da rimuovere dopo aver levato il commento sotto

        // if (strchr(email, '.') != NULL && strchr(email, '@') != NULL)
        // {
        //     valid = true;
        //     std::cout << "Valid email" << std::endl;
        //        len_data = strlen(email);                
        // }
        // else
        // {
        //     std::cout << "Not a valid email, try again. Email must contain at least one '.' and one '@' character." << std::endl;
        // }
        len_data = strlen(email);   //da cancellare quando si toglie il commento sopra
    }
    valid = false;
    while (!valid)
    {
        std::cout << "Enter password (max 10 caratteri): ";
        std::cin.getline(password, sizeof(password));
        if (std::cin.fail())
        {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }
        // controlla se la password contiene almeno un numero e una lettera e un carattere speciale

        valid = true; //da rimuovere dopo aver levato il commento sotto

        // std::cout << "Checking if the given password is valid... ";
        // if (strpbrk(password, "0123456789") != NULL && strpbrk(password, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") != NULL && strpbrk(password, "!@#$%^&*") != NULL && strlen(password) >= 8)
        // {
        //     valid = true;
        //     std::cout << "Valid password" << std::endl;
        //        len_data += strlen(password);
        // }
        // else
        // {
        //     std::cout << "Not a valid password, try again. Password must contain at least one number, one letter and one special character." << std::endl;
        // }
    }
    // valid = false;
    // while (!valid)
    // {
    //     std::cout << "Please repeat the inserted password: ";
    //     std::cin.getline(password_check, sizeof(password));
    //     if (std::cin.fail())
    //     {
    //         std::cin.clear();
    //         std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    //     }
    //     if (strcmp(password, password_check) == 0)
    //     {
    //         valid = true;
    //     }
    //     else
    //     {
    //         std::cout << "Passwords do not match, try again." << std::endl;
    //     }
    // }
    len_data += strlen(password);   //da cancellare quando si toglie il commento sopra
    std::cout << "Enter username (max 20 caratteri): ";
    std::cin.getline(username, sizeof(username));
    if (std::cin.fail())
    {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
    len_data += strlen(username);

    std::string requestStr = std::to_string(0) + "|" + std::to_string(len_data) + "|" + std::string(email) + "|" + std::string(password) + "|" + std::string(username);
    /*std::cout << "requestStr size: " << requestStr.size() << std::endl;
    std::cout << "requestStr: ";
    for (auto i : requestStr)
        std::cout << i;
    std::cout << std::endl << std::endl;*/


    return requestStr;
}