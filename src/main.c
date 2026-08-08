#include <stdio.h>
#include <unistd.h>
#include <net/if.h>

#include "../include/tun.h"
#include "../include/ipv4.h"
#include "../include/checksum.h"
#include "../include/classifier.h"

// --- Import Telemetry from classifier.c ---
extern int icmp_rx_p, icmp_rx_b, icmp_tx_p, icmp_tx_b;
extern int udp_rx_p, udp_rx_b, udp_tx_p, udp_tx_b;
extern int tcp_rx_p, tcp_rx_b, tcp_tx_p, tcp_tx_b;
extern int tot_rx_p, tot_rx_b, tot_tx_p, tot_tx_b;

extern char tcp_state[32];
extern char active_conn[64];
extern uint32_t current_seq;
extern uint32_t current_ack;

extern int non_ipv4_drops;
extern int bad_checksums;
extern int unknown_drops;
extern char last_event[128];

int main() {
    char tun_name[IFNAMSIZ] = "tun0";
    int tun_fd = tun_alloc(tun_name);

    // Initial clear screen before starting
    printf("\033[2J\033[H");
    printf("[*] NetStacc Started. Listening on %s ...\n", tun_name);

    unsigned char buffer[2048];

    while (1) {
        int nread = read(tun_fd, buffer, sizeof(buffer));
        if (nread < 0) continue;

        uint8_t ip_version = (buffer[0] >> 4) & 0x0F;
        if (ip_version != 4) {
            non_ipv4_drops++; 
            continue; 
        }

        struct ipv4_header *ip = (struct ipv4_header *)buffer;

        if (verify_ip_checksum(ip) != 1) {
            bad_checksums++; 
            continue; 
        }

        // 1. Process the packet and update our global variables
        classify_protocol(ip, buffer, tun_fd);

        // 2. Compute Totals
        tot_rx_p = icmp_rx_p + udp_rx_p + tcp_rx_p;
        tot_rx_b = icmp_rx_b + udp_rx_b + tcp_rx_b;
        tot_tx_p = icmp_tx_p + udp_tx_p + tcp_tx_p;
        tot_tx_b = icmp_tx_b + udp_tx_b + tcp_tx_b;

        // 3. Render the Live TUI (Clears screen and draws at the top)
        printf("\033[2J\033[H");
        printf("\033[35m");
        printf("  _   _      _   ____  _                   \n");
        printf(" | \\ | | ___| |_/ ___|| |_ __ _  ___ ___   \n");
        printf(" |  \\| |/ _ \\ __\\___ \\| __/ _` |/ __/ __|  \n");
        printf(" | |\\  |  __/ |_ ___) | || (_| | (_| (__   \n");
        printf(" |_| \\_|\\___|\\__|____/ \\__\\__,_|\\___\\___|  \n");
        printf("\033[0m\n"); 

        printf("Target Device: tun0 | Mode: Active | Telemetry: Live\n");
        printf("----------------------------------------------------------------\n");
        printf("PROTOCOL        RX PACKETS   RX BYTES    TX PACKETS   TX BYTES  \n");
        printf("----------------------------------------------------------------\n");
        
        printf("ICMP (Ping)     %-12d %-11d %-12d %-11d\n", icmp_rx_p, icmp_rx_b, icmp_tx_p, icmp_tx_b);
        printf("UDP  (App)      %-12d %-11d %-12d %-11d\n", udp_rx_p, udp_rx_b, udp_tx_p, udp_tx_b);
        printf("TCP  (Stack)    %-12d %-11d %-12d %-11d\n", tcp_rx_p, tcp_rx_b, tcp_tx_p, tcp_tx_b);
        printf("----------------------------------------------------------------\n");
        printf("TOTALS          %-12d %-11d %-12d %-11d\n", tot_rx_p, tot_rx_b, tot_tx_p, tot_tx_b);

        printf("\nDROP DIAGNOSTICS\n");
        printf("----------------------------------------------------------------\n");
        printf("Non-IPv4 Traffic : \033[31m%d\033[0m\n", non_ipv4_drops); 
        printf("Bad Checksums    : \033[31m%d\033[0m\n", bad_checksums);
        printf("Unknown Protocols: \033[31m%d\033[0m\n", unknown_drops);
        printf("----------------------------------------------------------------\n");

        printf("ACTIVE TCP CONNECTION\n");
        printf("----------------------------------------------------------------\n");
        printf("Target          : %s\n", active_conn);
        printf("State           : %s\n", tcp_state);
        printf("Seq Number      : %u\n", current_seq);
        printf("Ack Number      : %u\n", current_ack);
        printf("Last Action     : HTTP 200 OK Response Sent\n");
        printf("----------------------------------------------------------------\n");
        
        // The static event log replaces the scrolling logs
        printf("LATEST EVENT     : \033[36m%s\033[0m\n", last_event);

        printf("\n\033[35m> Waiting for raw packets ...\033[0m\n");
    }

    return 0;
}
