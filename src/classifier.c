#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include "../include/ipv4.h"
#include "../include/icmp.h"
#include "../include/udp.h"
#include "../include/tcp.h"
#include "../include/tcp_state.h"
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

// UPDATED
void handle_tcp(struct ipv4_header *ip, uint8_t *payload, int len, int tun_fd, uint8_t *buf) {
    int ip_header_len = (ip->version_ihl & 0x0f) * 4;
    int total_len = ip_header_len + len; 
    struct tcp_header *tcp = parse_tcp(buf, ip, total_len);
    if (!tcp) {
        live_stats.drops.malformed++;
        return;
    }

    if (!verify_tcp_checksum(ip, tcp, len)) {
        live_stats.drops.bad_checksum++;
        return;
    }

    // Track valid TCP RX metrics
    live_stats.tcp.rx_packets++;
    live_stats.tcp.rx_bytes += ntohs(ip->total_length);

    struct tcp_connection *conn = tcp_state_machine(tcp, ip->src_ip, ip->dest_ip);
    if (!conn) return; 

    uint8_t flags_to_send;
    switch (conn->state) {
        case TCP_SYN_RCVD:   flags_to_send = TCP_SYN | TCP_ACK; break; // completing handshake
        case TCP_CLOSE_WAIT: flags_to_send = TCP_ACK;           break; // acking their FIN
        default: return;     }


    struct tcp_header *tcp_out = (struct tcp_header *)(buf + ip_header_len);
    build_tcp_response(tcp_out, conn, flags_to_send);
    reply_tcp_finalize(ip, tcp_out, sizeof(struct tcp_header));

    int reply_len = ip_header_len + (int)sizeof(struct tcp_header);
    int bytes_written = write(tun_fd, buf, reply_len);

    if (bytes_written > 0) {
        live_stats.tcp.tx_packets++;
        live_stats.tcp.tx_bytes += bytes_written;
        live_stats.total_tx_packets++;
        live_stats.total_tx_bytes += bytes_written;
    }
}

void handle_udp(struct ipv4_header *ip, uint8_t *payload, int len) {
    struct udp_header *udp = (struct udp_header *) payload;
    // Verify UDP checksum; drop and log if invalid
    if (!verify_udp_checksum(ip, udp, len)) {
        live_stats.drops.bad_checksum++;
        return;
    }
    // Track valid UDP RX metrics
    live_stats.udp.rx_packets++;
    live_stats.udp.rx_bytes += ntohs(ip->total_length);
}

void classify_protocol(struct ipv4_header *ip, uint8_t *buf, int tun_fd, int nread) {
    int header_len = (ip->version_ihl & 0x0f) * 4;
    int total_len  = ntohs(ip->total_length);

    if (header_len < 20 || total_len < header_len || total_len > nread) {
        live_stats.drops.malformed++;
        return;
    }

    int payload_len = total_len - header_len;
    uint8_t *payload = buf + header_len;

    switch (ip->protocol) {
        case IPPROTO_ICMP:
            handle_icmp(ip, buf, tun_fd);
            break;
        case IPPROTO_TCP:
            // UPDATED
            handle_tcp(ip, payload, payload_len, tun_fd, buf);
            break;
        case IPPROTO_UDP:
            handle_udp(ip, payload, payload_len);
            break;
        default:
            live_stats.drops.unknown_proto++;
            break;
    }
}
