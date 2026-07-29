#ifndef UDP_H
#define UDP_H
#include <stdint.h>

struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed));

struct udp_pseudo_header {
    uint32_t src_ip;
    uint32_t dest_ip;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t udp_length;
} __attribute__((packed));

struct udp_header* parse_udp(uint8_t *buffer, struct ipv4_header *ip_header);
uint16_t compute_udp_checksum(struct ipv4_header *ip_header, struct udp_header *udp_header, int udp_len);

#endif

