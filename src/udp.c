#include <string.h>
#include <netinet/in.h>
#include "../include/ipv4.h"
#include "../include/checksum.h"
#include "../include/udp.h"

/* Same pattern as parse_icmp: no copying, just points at the offset
 * right after the IP header ends. */
struct udp_header* parse_udp(uint8_t *buffer, struct ipv4_header *ip_header) {
    int ip_header_len = (ip_header->version_ihl & 0x0f) * 4;
    uint8_t *udp_data = buffer + ip_header_len;
    return (struct udp_header *) udp_data;
}

/* Builds the 12-byte pseudo-header, glues it in front of the real UDP
 * header + data, then reuses the SAME compute_checksum() from checksum.c
 * that verify_ip_checksum() and reply_icmp() already use. */
uint16_t compute_udp_checksum(struct ipv4_header *ip_header, struct udp_header *udp_header, int udp_len) {
    uint8_t buf[2048];
    struct udp_pseudo_header ph;

    ph.src_ip     = ip_header->src_ip;
    ph.dest_ip    = ip_header->dest_ip;
    ph.zero       = 0;
    ph.protocol   = IPPROTO_UDP;
    ph.udp_length = htons(udp_len);

    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), udp_header, udp_len);

    return compute_checksum(buf, sizeof(ph) + udp_len);
}
