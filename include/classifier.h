#ifndef CLASSIFIER_H
#define CLASSIFIER_H

#include <stdint.h>
#include "ipv4.h"

void classify_protocol(struct ipv4_header *ip, uint8_t *buf, int tun_fd);

#endif
