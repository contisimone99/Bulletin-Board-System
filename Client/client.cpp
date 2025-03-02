#include "client.h"

struct file_descriptor_set
{
    fd_set master;
    fd_set read_fds;
    int fdmax;
} fds;

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cerr << "Missing ports\n";
        exit(-1);
    }
    if (atoi(argv[1]) < 1024 )
    {
        std::cerr << "The port you input is reserved, try something else\n";
        exit(-1);
    }
    int server_port = atoi(argv[1]);
    Client client(server_port);
    client.run();
    return 0;
}