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
    switch (ip->protocol) {
        case IPPROTO_ICMP:
            handle_icmp(ip, buf, tun_fd);
            break;
        case IPPROTO_TCP:
            handle_tcp(ip, buf, ntohs(ip->total_length));
            break;
        case IPPROTO_UDP:
            handle_udp(ip, buf, ntohs(ip->total_length));
            break;
        default:
            printf("  -> unknown protocol %d, dropping\n", ip->protocol);
    }
}
