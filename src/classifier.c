#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "../include/ipv4.h"
#include "../include/classifier.h"

/* SECTION 4: Protocol classifier */

void handle_icmp(struct ipv4_header *ip, uint8_t *buf, int tun_fd);

void handle_tcp(struct ipv4_header *ip, uint8_t *payload, int len) {
    printf("  -> TCP packet (not built yet, this is Week 4)\n");
}

void handle_udp(struct ipv4_header *ip, uint8_t *payload, int len) {
    printf("  -> UDP packet (not built yet, this is Week 3)\n");
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
            printf("  -> unknown protocol %d, dropping\n", ip->protocol);
    }
}
