#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include "ipv4.h"

struct tcp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset_reserved;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} __attribute__((packed));

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

struct tcp_pseudo_header {
    uint32_t src_ip;
    uint32_t dest_ip;
    uint8_t  zero;
    uint8_t  protocol;    // 6 for TCP
    uint16_t tcp_length;  // TCP header + payload length
} __attribute__((packed));

static inline int tcp_header_len(const struct tcp_header *tcp) {
    return ((tcp->data_offset_reserved >> 4) & 0x0F) * 4;
}

struct tcp_header *parse_tcp(uint8_t *buffer, struct ipv4_header *ip_header, int packet_len);
uint8_t *tcp_payload(uint8_t *buffer, struct ipv4_header *ip_header, struct tcp_header *tcp);


uint16_t compute_tcp_checksum(struct ipv4_header *ip_header, struct tcp_header *tcp, int segment_len);
int verify_tcp_checksum(struct ipv4_header *ip_header, struct tcp_header *tcp, int segment_len);

void reply_tcp_finalize(struct ipv4_header *ip_header, struct tcp_header *tcp, int tcp_len);

#endif
