#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include "../include/ipv4.h"
#include "../include/icmp.h"
#include "../include/udp.h"
#include "../include/classifier.h"
#include "../include/dashboard.h"

void handle_icmp(struct ipv4_header *ip, uint8_t *buf, int tun_fd) {
    struct icmp_header* icmp_header;
    if ((icmp_header = parse_icmp(buf, ip)) == NULL) {
        return; // Drop invalid ICMP packets
    }

    // Track ICMP RX metrics
    live_stats.icmp.rx_packets++;
    live_stats.icmp.rx_bytes += ntohs(ip->total_length);

    // Process Echo Request (Ping)
    if (icmp_header->type == 8) {
        reply_icmp(ip, icmp_header);
        int bytes_written = write(tun_fd, buf, ntohs(ip->total_length));
        
        // Track ICMP TX metrics
        if (bytes_written > 0) {
            live_stats.icmp.tx_packets++;
            live_stats.icmp.tx_bytes += bytes_written;
            live_stats.total_tx_packets++;
            live_stats.total_tx_bytes += bytes_written;
        }
    }
}

void handle_tcp(struct ipv4_header *ip, uint8_t *payload, int len) {
    // Track TCP RX metrics (Handshake implementation pending)
    live_stats.tcp.rx_packets++;
    live_stats.tcp.rx_bytes += ntohs(ip->total_length);
}

void handle_udp(struct ipv4_header *ip, uint8_t *payload, int len) {
    struct udp_header *udp = (struct udp_header *) payload;

    // Verify UDP checksum; drop and log if invalid
    if (compute_udp_checksum(ip, udp, len) != 0) {
        live_stats.drops.bad_checksum++;
        return; 
    }

    // Track valid UDP RX metrics
    live_stats.udp.rx_packets++;
    live_stats.udp.rx_bytes += ntohs(ip->total_length);
}

void classify_protocol(struct ipv4_header *ip, uint8_t *buf, int tun_fd) {
    int header_len = (ip->version_ihl & 0x0f) * 4;
    int payload_len = ntohs(ip->total_length) - header_len;
    uint8_t *payload = buf + header_len;

    switch (ip->protocol) {
        case IPPROTO_ICMP:
            handle_icmp(ip, buf, tun_fd);
            break;
        case IPPROTO_TCP:
            handle_tcp(ip, payload, payload_len);
            break;
        case IPPROTO_UDP:
            handle_udp(ip, payload, payload_len);
            break;
        default:
            live_stats.drops.unknown_proto++;
            break;
    }
}
