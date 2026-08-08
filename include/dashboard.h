#ifndef DASHBOARD_H
#define DASHBOARD_H

#include <stdint.h>
#include <time.h>

// Struct for individual protocol stats
typedef struct {
    unsigned long rx_packets;
    unsigned long rx_bytes;
    unsigned long tx_packets;
    unsigned long tx_bytes;
} proto_stats_t;

// Struct for dropped packets
typedef struct {
    unsigned long non_ipv4;
    unsigned long bad_checksum;
    unsigned long unknown_proto;
    unsigned long malformed;
} drop_stats_t;

// Main stats struct
typedef struct {
    time_t start_time;
    unsigned long total_rx_packets;
    unsigned long total_rx_bytes;
    unsigned long total_tx_packets;
    unsigned long total_tx_bytes;

    proto_stats_t icmp;
    proto_stats_t udp;
    proto_stats_t tcp;

    drop_stats_t drops;
} net_stats_t;

extern net_stats_t live_stats;

void init_dashboard();
void render_dashboard();

#endif
