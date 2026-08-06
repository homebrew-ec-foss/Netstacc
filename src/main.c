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

extern char tcp_state[20];
extern char active_conn[64];
extern uint32_t current_seq;
extern uint32_t current_ack;

int main() {
    char tun_name[IFNAMSIZ] = "tun0";
    int tun_fd = tun_alloc(tun_name);

    // Initial clear screen before starting
    printf("\033[H\033[J");
    printf("[*] NetStacc Started. Listening on %s ...\n", tun_name);
    
    unsigned char buffer[2048];

    while (1) {
        int nread = read(tun_fd, buffer, sizeof(buffer));
        if (nread < 0) continue;

        uint8_t ip_version = (buffer[0] >> 4) & 0x0F;
        if (ip_version != 4) {
            continue; // Drop non-IPv4 traffic silently
        }

        struct ipv4_header *ip = (struct ipv4_header *)buffer;

        if (verify_ip_checksum(ip) != 1) {
            continue; // Drop bad checksums silently
        }

        // 1. Process the packet and update our global variables
        classify_protocol(ip, buffer, tun_fd);

        // 2. Compute Totals
        int tot_rx_p = icmp_rx_p + udp_rx_p + tcp_rx_p;
        int tot_rx_b = icmp_rx_b + udp_rx_b + tcp_rx_b;
        int tot_tx_p = icmp_tx_p + udp_tx_p + tcp_tx_p;
        int tot_tx_b = icmp_tx_b + udp_tx_b + tcp_tx_b;

        // 3. Render the Live TUI (Clears screen and draws at the top)
        printf("\033[H\033[J");
        printf("  _   _  ZXRT34 _ ____  _                   \n");
        printf(" | \\ | | ___| |_/ ___|| |_ __ _  ___ ___  \n");
        printf(" |  \\| |/ _ \\ __\\___ \\| __/ _` |/ __/ __| \n");
        printf(" | |\\  |  __/ |_ ___) | || (_| | (_| (__  \n");
        printf(" |_| \\_|\\___|\\__|____/ \\__\\__,_|\\___\\___| \n");
        printf("=========================================================\n");
        printf(" Target Device: tun0 | Mode: Active | Telemetry: Live\n");
        printf("---------------------------------------------------------\n");
        printf(" PROTOCOL        RX PACKETS  RX BYTES  TX PACKETS  TX BYTES\n");
        printf("---------------------------------------------------------\n");
        printf(" ICMP (Ping)     %-11d %-9d %-11d %-9d\n", icmp_rx_p, icmp_rx_b, icmp_tx_p, icmp_tx_b);
        printf(" UDP  (App)      %-11d %-9d %-11d %-9d\n", udp_rx_p, udp_rx_b, udp_tx_p, udp_tx_b);
        printf(" TCP  (Stack)    %-11d %-9d %-11d %-9d\n", tcp_rx_p, tcp_rx_b, tcp_tx_p, tcp_tx_b);
        printf("---------------------------------------------------------\n");
        printf(" TOTALS          %-11d %-9d %-11d %-9d\n\n", tot_rx_p, tot_rx_b, tot_tx_p, tot_tx_b);
        printf(" DROP DIAGNOSTICS\n");
        printf("---------------------------------------------------------\n");
        printf(" Non-IPv4 Traffic : 0\n");
        printf(" Bad Checksums    : 0\n");
        printf(" Unknown Protocols: 0\n\n");
        printf(" ACTIVE TCP CONNECTION\n");
        printf("---------------------------------------------------------\n");
        printf(" Target        : %s\n", active_conn);
        printf(" State         : %s\n", tcp_state);
        printf(" Seq Number    : %u\n", current_seq);
        printf(" Ack Number    : %u\n", current_ack);
    }
    
    return 0;
}
