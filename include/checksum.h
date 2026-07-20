#ifndef CHECKSUM_H
#define CHECKSUM_H

#include "ipv4.h"

uint16_t compute_checksum(void *data, int len);
int verify_ip_checksum(struct ipv4_header *ip);

#endif
