#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include "../include/tun.h"
#include "../include/ipv4.h" 
#include "../include/classifier.h" 
#include "../include/checksum.h"
int main() {
    char tun_name[IFNAMSIZ] = "tun0";
    int tun_fd = tun_alloc(tun_name);
    
    printf("[*] NetStacc Started. Listening on %s...\n", tun_name);
    unsigned char buffer[2048]; 

    while (1) {
        int nread = read(tun_fd, buffer, sizeof(buffer));
        if (nread < 0) continue;

	uint8_t ip_version = (buffer[0] >> 4) & 0x0F;
        if (ip_version != 4) {
            continue; // Drop IPv6 (e.g. protocol 128) and non-IPv4 traffic
        }

        // Cast the raw bucket into our structured IPv4 glasses
        struct ipv4_header *ip = (struct ipv4_header *)buffer;

        // Print the protocol number! (1 = ICMP, 6 = TCP, 17 = UDP)
        printf(" -> Captured %d bytes | Protocol: %d\n", nread, ip->protocol);
	
	if (verify_ip_checksum(ip) != 1) {
    		printf("    [!] Bad Checksum! Dropping packet.\n");
    		continue; // Throw it away and start the loop over
	}
    }
    return 0;
}
