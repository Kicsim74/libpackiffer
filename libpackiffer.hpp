#include <string>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

const int ALL  =  0x0003;
const int IP   =  0x0800;
const int ARP  =  0x0806;
const int RARP =  0x8035;
const int LOOP =  0x0060;	

const int PACKET_LENGTH = 65535;

const int DISPLAY_IN_TERMINAL = 0;
const int DUMP_IN_FILE = 1;
const int DISPLAY_AND_DUMP = 2;

int create_socket(int protocol);
int set_socket_options(int socket_descriptor, int promiscuous, const char * interface, int protocol);
void sniff_socket(int socket_descriptor, int ifr_index);