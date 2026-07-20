#include <stdint.h>
#include "../include/ipv4.h"
#include "../include/checksum.h"

/* SECTION 3: checksum */

uint16_t compute_checksum(void *data, int len) {
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)data;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(uint8_t *)ptr;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

int verify_ip_checksum(struct ipv4_header *ip) {
    int header_len = (ip->version_ihl & 0x0f) * 4;
    uint16_t result = compute_checksum(ip, header_len);
    return result == 0;
}
