#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include "ipv4.h"
#include "icmp.h"
#include "udp.h"
#include "classifier.h"
void handle_icmp(struct ipv4_header *ip, uint8_t *buf, int tun_fd){
    struct icmp_header* icmp_header ;
    if ((icmp_header = parse_icmp(buf,ip))==NULL){
        printf("ERR: ICMP header is invalid");
        return;
    }
    printf(" -> ICMP packet\n");
    printf("\tid : %d\n"
           "\tSequence number : %d\n"
           "\tType : %d\n"
           "\tCode : %d\n",
           ntohs(icmp_header->id),
           ntohs(icmp_header->sqnum),
           (icmp_header->type),
           icmp_header->code);
    if (icmp_header->type == 8){
        reply_icmp(ip, icmp_header);
        write(tun_fd, buf, ntohs(ip->total_length));
        printf(" -> reply ICMP packet sent\n");
    }
}
void handle_tcp(struct ipv4_header *ip, uint8_t *payload, int len) {
    printf("  -> TCP packet (not built yet, this is Week 4)\n");
}
void handle_udp(struct ipv4_header *ip, uint8_t *payload, int len) {
    struct udp_header *udp = (struct udp_header *) payload;

    printf(" -> UDP packet\n");
    printf("\tSrc port : %d\n"
           "\tDst port : %d\n"
           "\tLength   : %d\n"
           "\tChecksum : 0x%04x\n",
           ntohs(udp->src_port),
           ntohs(udp->dst_port),
           ntohs(udp->length),
           ntohs(udp->checksum));

    uint16_t result = compute_udp_checksum(ip, udp, len);
    if (result == 0) {
        printf(" -> UDP checksum: OK\n");
    } else {
        printf(" -> UDP checksum: INVALID (result=0x%04x)\n", result);
    }
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
