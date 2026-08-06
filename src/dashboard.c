#include <stdio.h>
#include <time.h>
#include "../include/dashboard.h"

#define C_PINK_BRIGHT "\033[38;5;213m"
#define C_PINK_DARK   "\033[38;5;161m"
#define C_CYAN        "\033[38;5;45m"
#define C_GRAY        "\033[38;5;240m"
#define C_WHITE       "\033[1;37m"
#define C_RED         "\033[38;5;196m"
#define C_RESET       "\033[0m"

// Initialize the global struct
net_stats_t live_stats = {0};

void init_dashboard() {
    live_stats.start_time = time(NULL);
    printf("\033[2J\033[H"); // Clear screen
}

void render_dashboard() {
    printf("\033[H"); // Move cursor to top left

    // Calculate Uptime & Rate
    time_t now = time(NULL);
    long uptime = (long)difftime(now, live_stats.start_time);
    int hrs = uptime / 3600;
    int mins = (uptime % 3600) / 60;
    int secs = uptime % 60;
    long rate = (uptime > 0) ? (live_stats.total_rx_packets / uptime) : live_stats.total_rx_packets;

    printf(C_GRAY "=================================================================\n" C_RESET);
    printf("%s  _    _      _   _____ _                  \n", C_PINK_BRIGHT);
    printf(" | \\ | |    | | / ____| |                 \n");
    printf(" |  \\| | ___| || (___ | |_ __ _  ___ ___  \n");
    printf(" | . ` |/ _ \\ __\\___ \\| __/ _` |/ __/ __| \n");
    printf(" | |\\  |  __/ |_____) | || (_| | (_| (__  \n");
    printf(" |_| \\_|\\___|\\__|____/ \\__\\__,_|\\___\\___| \n%s", C_RESET);
    printf(C_GRAY "=================================================================\n" C_RESET);

    // Status Bar
    printf("  Target Device: %stun0%s | Uptime: %02d:%02d:%02d | Rate: %ld pkts/s\n", 
           C_WHITE, C_RESET, hrs, mins, secs, rate);
    printf(C_GRAY "-----------------------------------------------------------------\n" C_RESET);

    // Table Header
    printf("  PROTOCOL         RX PACKETS   RX BYTES    TX PACKETS   TX BYTES\n");
    printf(C_GRAY "  ---------------------------------------------------------------\n" C_RESET);

    printf("  ICMP (Ping)      %-13lu %-11lu %-13lu %-10lu\n",
           live_stats.icmp.rx_packets, live_stats.icmp.rx_bytes,
           live_stats.icmp.tx_packets, live_stats.icmp.tx_bytes);

    printf("  UDP (App)        %-13lu %-11lu %-13lu %-10lu\n",
           live_stats.udp.rx_packets, live_stats.udp.rx_bytes,
           live_stats.udp.tx_packets, live_stats.udp.tx_bytes);

    printf("  TCP (Stack)      %-13lu %-11lu %-13lu %-10lu\n",
           live_stats.tcp.rx_packets, live_stats.tcp.rx_bytes,
           live_stats.tcp.tx_packets, live_stats.tcp.tx_bytes);

    printf(C_GRAY "  ---------------------------------------------------------------\n" C_RESET);
    printf("  TOTALS           %-13lu %-11lu %-13lu %-10lu\n",
           live_stats.total_rx_packets, live_stats.total_rx_bytes,
           live_stats.total_tx_packets, live_stats.total_tx_bytes);

    printf(C_GRAY "\n  DROP DIAGNOSTICS\n" C_RESET);
    printf(C_GRAY "  ---------------------------------------------------------------\n" C_RESET);
    printf("  Non-IPv4 Traffic : %s%lu%s\n", C_RED, live_stats.drops.non_ipv4, C_RESET);
    printf("  Bad Checksums    : %s%lu%s\n", C_RED, live_stats.drops.bad_checksum, C_RESET);
    printf("  Unknown Protocols: %s%lu%s\n", C_RED, live_stats.drops.unknown_proto, C_RESET);
    
    printf(C_GRAY "  ===============================================================\n" C_RESET);
    printf("%s  > Waiting for raw packets... \n", C_PINK_BRIGHT);
    printf(C_RESET);
}
