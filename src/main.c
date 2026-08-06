#include <stdio.h>
#include <unistd.h>
#include <net/if.h>

#include "../include/tun.h"
#include "../include/ipv4.h"
#include "../include/checksum.h"
#include "../include/classifier.h"
#include "../include/dashboard.h" // Added Dashboard Header

int main() {
    char tun_name[IFNAMSIZ] = "tun0";
    int tun_fd = tun_alloc(tun_name);

    unsigned char buffer[2048];

    // Initialize the advanced dashboard UI
    init_dashboard(); 

    while (1) {
        int nread = read(tun_fd, buffer, sizeof(buffer));
        if (nread < 0) continue;

        // Global RX update
        live_stats.total_rx_packets++;
        live_stats.total_rx_bytes += nread;

        uint8_t ip_version = (buffer[0] >> 4) & 0x0F;
        if (ip_version != 4) {
            live_stats.drops.non_ipv4++; // Log drop
            render_dashboard();
            continue; // Drop IPv6 and non-IPv4 traffic
        }

        // Cast the raw bucket into our structured IPv4 glasses
        struct ipv4_header *ip = (struct ipv4_header *)buffer;

        if (verify_ip_checksum(ip) != 1) {
            live_stats.drops.bad_checksum++; // Log drop
            render_dashboard();
            continue; // Throw it away and start the loop over
        }

        // Send to Aishwarya's classifier
        classify_protocol(ip, buffer, tun_fd);
        
        // Refresh the screen after processing the packet
        render_dashboard(); 
    }
    
    return 0;
}
