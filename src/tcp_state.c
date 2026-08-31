#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>   
#include "../include/tcp_state.h"

static struct tcp_connection *conn_table = NULL;


static int rng_seeded = 0;
static void ensure_seeded(void) {
    if (!rng_seeded) {
        srand((unsigned int)time(NULL));
        rng_seeded = 1;
    }
}

struct tcp_connection *find_connection(uint32_t src_ip, uint32_t dest_ip,
                                        uint16_t src_port, uint16_t dest_port) {
    struct tcp_connection *c = conn_table;
    while (c) {
        if (c->src_ip == src_ip && c->dest_ip == dest_ip &&
            c->src_port == src_port && c->dest_port == dest_port) {
            return c;
        }
        c = c->next;
    }
    return NULL;
}

struct tcp_connection *create_connection(uint32_t src_ip, uint32_t dest_ip,
                                          uint16_t src_port, uint16_t dest_port) {
    ensure_seeded();

    struct tcp_connection *c = malloc(sizeof(struct tcp_connection));
    if (!c) {
        return NULL;
    }
    c->src_ip = src_ip;
    c->dest_ip = dest_ip;
    c->src_port = src_port;
    c->dest_port = dest_port;
    c->state = TCP_LISTEN;
    c->my_seq = rand(); 
    c->their_seq = 0;
    c->next = conn_table;
    conn_table = c;
    return c;
}



void build_tcp_response(struct tcp_header *out, struct tcp_connection *conn,
                         uint8_t flags) {
    memset(out, 0, sizeof(struct tcp_header));
    out->src_port = conn->dest_port;   
    out->dest_port = conn->src_port;
    out->seq_num = htonl(conn->my_seq);
    out->ack_num = htonl(conn->their_seq);
    out->data_offset_reserved = (5 << 4); 
    out->flags = flags;
    out->window = htons(65535); 
    out->checksum = 0; 
    out->urgent_ptr = 0;
}


struct tcp_connection *tcp_state_machine(struct tcp_header *tcp,
                                          uint32_t src_ip, uint32_t dest_ip) {
    uint16_t sport = ntohs(tcp->src_port);
    uint16_t dport = ntohs(tcp->dest_port);
    uint32_t seq = ntohl(tcp->seq_num);
    uint32_t ack = ntohl(tcp->ack_num);

    struct tcp_connection *conn = find_connection(src_ip, dest_ip, sport, dport);

  
    if (!conn && (tcp->flags & TCP_SYN)) {
        conn = create_connection(src_ip, dest_ip, sport, dport);
        if (!conn) return NULL;
        conn->their_seq = seq + 1;   
        conn->state = TCP_SYN_RCVD;
        return conn; 
    }

    if (!conn) return NULL; 

    switch (conn->state) {

        case TCP_SYN_RCVD:
            
            if ((tcp->flags & TCP_ACK) && ack == conn->my_seq + 1) {
                conn->my_seq += 1;
                conn->state = TCP_ESTABLISHED;
                
            }
            return NULL;

        case TCP_ESTABLISHED:
            
            if (tcp->flags & TCP_FIN) {
                conn->their_seq += 1;
                conn->state = TCP_CLOSE_WAIT;
                return conn;
            }
            return NULL;

        default:
            return NULL;
    }
}
