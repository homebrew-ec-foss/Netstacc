#ifndef TCP_STATE_H
#define TCP_STATE_H

#include <stdint.h>
#include "tcp.h"



enum tcp_state {
    TCP_LISTEN,
    TCP_SYN_RCVD,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_CLOSED
};

struct tcp_connection {
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;

    enum tcp_state state;

    uint32_t my_seq;      
    uint32_t their_seq;   

    struct tcp_connection *next; 
};


struct tcp_connection *find_connection(uint32_t src_ip, uint32_t dest_ip,
                                        uint16_t src_port, uint16_t dest_port);

struct tcp_connection *create_connection(uint32_t src_ip, uint32_t dest_ip,
                                          uint16_t src_port, uint16_t dest_port);



void build_tcp_response(struct tcp_header *out, struct tcp_connection *conn,
                         uint8_t flags);



struct tcp_connection *tcp_state_machine(struct tcp_header *tcp,
                                          uint32_t src_ip, uint32_t dest_ip);

#endif
