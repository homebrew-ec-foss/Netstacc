#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include "../include/tun.h"
#include "../include/ipv4.h" // Added this!

int main() {
    char tun_name[IFNAMSIZ] = "tun0";
    int tun_fd = tun_alloc(tun_name);
    
    printf("[*] NetStacc Started. Listening on %s...\n", tun_name);
    unsigned char buffer[2048]; 

    while (1) {
        int nread = read(tun_fd, buffer, sizeof(buffer));
        if (nread < 0) continue;

        // Cast the raw bucket into our structured IPv4 glasses
        struct ipv4_header *ip = (struct ipv4_header *)buffer;

        // Print the protocol number! (1 = ICMP, 6 = TCP, 17 = UDP)
        printf(" -> Captured %d bytes | Protocol: %d\n", nread, ip->protocol);
    }
    return 0;
}
