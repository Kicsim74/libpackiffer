#include "libpackiffer.hpp"

int main()
{
    std::string ifname {"eth0"};
    int socket = create_socket(ALL);
    int interface = set_socket_options(socket, 1, ifname.c_str(), ALL);
    sniff_socket(socket, interface);
    return 0;
}