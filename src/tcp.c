<<<<<<< HEAD
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
=======
#include <string.h>
#include <netinet/in.h>
>>>>>>> 71b7b9f (feat: parses tcp header)
#include "../include/ipv4.h"
#include "../include/checksum.h"
#include "../include/tcp.h"

struct tcp_header *parse_tcp(uint8_t *buffer, struct ipv4_header *ip_header, int packet_len) {
    int ip_header_len = (ip_header->version_ihl & 0x0f) * 4;
    uint8_t *tcp_data = buffer + ip_header_len;
    int remaining_len = packet_len - ip_header_len;

    if (remaining_len < (int)sizeof(struct tcp_header)) {
        return NULL; 
    }

    struct tcp_header *tcp = (struct tcp_header *) tcp_data;
    int hlen = tcp_header_len(tcp);
    if (hlen < 20 || hlen > remaining_len) {
        return NULL; 
    }
    return tcp;
}

uint8_t *tcp_payload(uint8_t *buffer, struct ipv4_header *ip_header, struct tcp_header *tcp) {
    int ip_header_len = (ip_header->version_ihl & 0x0f) * 4;
    return buffer + ip_header_len + tcp_header_len(tcp);
}
int verify_tcp_checksum(struct ipv4_header *ip_header, struct tcp_header *tcp, int segment_len) {
    struct tcp_pseudo_header pseudo;
    pseudo.src_ip     = ip_header->src_ip;
    pseudo.dest_ip    = ip_header->dest_ip;
    pseudo.zero       = 0;
    pseudo.protocol   = IPPROTO_TCP;
    pseudo.tcp_length = htons(segment_len);

    int total_len = sizeof(pseudo) + segment_len;
    uint8_t *buf = malloc(total_len);
    if (!buf) return 0;

    memcpy(buf, &pseudo, sizeof(pseudo));
    memcpy(buf + sizeof(pseudo), tcp, segment_len);

    uint16_t result = compute_checksum(buf, total_len);
    free(buf);
    return result == 0;
}
