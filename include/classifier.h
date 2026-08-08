#ifndef CLASSIFIER_H
#define CLASSIFIER_H

#include <stdint.h>
#include "ipv4.h"

void handle_icmp(struct ipv4_header *ip, uint8_t *buf, int tun_fd);

// UPDATED
void handle_tcp(struct ipv4_header *ip, uint8_t *payload, int len, int tun_fd, uint8_t *buf);

void handle_udp(struct ipv4_header *ip, uint8_t *payload, int len);

void classify_protocol(struct ipv4_header *ip, uint8_t *buf, int tun_fd, int nread);

#endif
