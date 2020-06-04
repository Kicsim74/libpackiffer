#include "libpackiffer.hpp"

int create_socket(int protocol){
     
    // create PF_PACKET socket 
    if (protocol == ALL || protocol == IP || protocol == ARP || protocol == RARP){

        int libpackiffersocket = socket(AF_PACKET, SOCK_RAW, htons(protocol));

        if (libpackiffersocket < 0){

            printf("Error: %s",strerror(errno));
            exit(1);

        }

        return libpackiffersocket;

    }

    else {

        printf("Error: unsupported protocol!");
        exit(1);

    }

}

int set_socket_options(int socket_descriptor, int promiscuous, const char * interface, int protocol){

    // get interface index
    struct ifreq sifr;

    memset(&sifr, 0, sizeof(sifr));
    strncpy(sifr.ifr_name, interface, sizeof(sifr.ifr_name));

    if (ioctl(socket_descriptor, SIOCGIFINDEX, &sifr) == -1)
    {
	    printf("Error: %s",strerror(errno));
        exit(1);
    }

    // fill link layer hedaer
    struct sockaddr_ll psll;

    memset(&psll, 0, sizeof(psll));
    psll.sll_family = PF_PACKET;
    psll.sll_ifindex = sifr.ifr_ifindex;
    psll.sll_protocol = htons(protocol);

    if (bind(socket_descriptor, (struct sockaddr *)&psll, sizeof(psll)) == -1)
    {
	    printf("Error: %s",strerror(errno));
        exit(1);
    }

    if (promiscuous == 1)
    {
        //enable promiscuous mode
        struct packet_mreq pmreq;

        memset(&pmreq, 0, sizeof(struct packet_mreq));
        pmreq.mr_type = PACKET_MR_PROMISC;
        pmreq.mr_ifindex = sifr.ifr_ifindex;

        if (setsockopt (socket_descriptor, SOL_SOCKET, PACKET_ADD_MEMBERSHIP, &pmreq, sizeof(struct packet_mreq)) < 0) {
	        printf("Error: %s",strerror(errno));
            exit(1);
        }
    }

    return sifr.ifr_ifindex;

}

void sniff_socket(int socket_descriptor, int ifr_index){

    struct sockaddr_ll from;
    socklen_t fromlen = sizeof(struct sockaddr_ll);

    char* buffer = (char*)malloc(PACKET_LENGTH); 
    int length = 0;  

    while (1)
    {

        length = recv(socket_descriptor, buffer, PACKET_LENGTH, 0);

        if (length == -1) 
        { 

            printf("Error: %s",strerror(errno));
            exit(1);

        }

        struct ethhdr *eth = (struct ethhdr *)(buffer);

        printf("\nEthernet Header\n");
        printf("\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
        printf("\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
        printf("\t|-Protocol : %d\n",ntohs(eth->h_proto));

        struct iphdr *ip = (struct iphdr*)( buffer + sizeof(struct ethhdr));
        struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
        struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));

        struct sockaddr_in source, dest;
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = ip->saddr;
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = ip->daddr;

        switch (ntohs(eth->h_proto)) {
        
        case 2048: // ip

            printf("\nIP Header\n");
            printf("\t|-Version : %d\n", (unsigned int)ip->version);
            printf("\t|-Internet Header Length : %d DWORDS or %d Bytes\n", (unsigned int)ip->ihl,((unsigned int)(ip->ihl))*4);
            printf("\t|-Type Of Service : %d\n", (unsigned int)ip->tos);
            printf("\t|-Total Length : %d Bytes\n", ntohs(ip->tot_len)); 
            printf("\t|-Identification : %d\n", ntohs(ip->id));
            printf("\t|-Time To Live : %d\n", (unsigned int)ip->ttl);
            printf("\t|-Protocol : %d\n", (unsigned int)ip->protocol);
            printf("\t|-Header Checksum : %d\n", ntohs(ip->check));
            printf("\t|-Source IP : %s\n", inet_ntoa(source.sin_addr));
            printf("\t|-Destination IP : %s\n", inet_ntoa(dest.sin_addr));

            switch ((unsigned int)ip->protocol) {
            
            case 17: // udp

                printf("\nUDP Header\n");
                printf("\t|-Source Port : %d\n", ntohs(udp->source));
                printf("\t|-Destination Port : %d\n", ntohs(udp->dest));
                printf("\t|-Length : %d\n", ntohs(udp->len));
                printf("\t|-Checksum : %d\n", ntohs(udp->check));

                break;
            
            case 6: // tcp

                printf("\nTCP Header\n");
                printf("\t|-Source Port : %d\n", ntohs(tcp->source));
                printf("\t|-Destination Port : %d\n", ntohs(tcp->dest));
                printf("\t|-Sequence Number : %d\n", ntohl(tcp->seq));
                printf("\t|-Acknowledgement Number : %d\n", ntohl(tcp->ack_seq));
                printf("\t|-Window : %d\n", ntohs(tcp->window));
                printf("\t|-Checksum : %d\n", ntohs(tcp->check));
                printf("\t|-Urgent Pointer : %d\n", ntohs(tcp->urg_ptr));
                printf("\t\t|-Data Offset : %d\n", ntohs(tcp->doff));
                printf("\t\t|-Reserved : %d\n", ntohs(tcp->res1));
                printf("\t\t|-Reserved : %d\n", ntohs(tcp->res2));
                printf("\t\tFlags\n");                             
                printf("\t\t|-No More Data From Sender : %d\n", ntohs(tcp->fin));
                printf("\t\t|-Synchronize Sequence Numbers : %d\n", ntohs(tcp->syn));
                printf("\t\t|-Reset The Connection : %d\n", ntohs(tcp->rst));
                printf("\t\t|-Push Function : %d\n", ntohs(tcp->psh));
                printf("\t\t|-Acknowledgment Field Significant : %d\n", ntohs(tcp->ack));
                printf("\t\t|-Urgent Pointer Field Significant : %d\n", ntohs(tcp->urg));

                break;
            }

            break;
        }
        
    }
    
}
