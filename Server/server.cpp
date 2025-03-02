#include "server.h"

int main(int argc, char *argv[])
{
    // Check if the correct number of arguments are provided
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <port>\n";
        return 1;
    }

    // Convert the port number from string to integer
    uint16_t port = std::stoi(argv[1]);

    if (port < 1024)
    {
        std::cerr << "Error: the port inserted is reserved!\n";
        exit(EXIT_FAILURE);
    }
    Server server(port);
    server.run();
    return 0;
}