#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include "checksum.h"
#include "ipv4.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"
#include "classifier.h"
void handle_icmp(struct ipv4_header *ip, uint8_t *buf, int tun_fd){
    struct icmp_header* icmp_header ;
    if ((icmp_header = parse_icmp(buf,ip))==NULL){
        printf("ERR: ICMP header is invalid");
        return;
    }
    printf(" -> ICMP packet\n");
    printf("\tid : %d\n"
           "\tSequence number : %d\n"
           "\tType : %d\n"
           "\tCode : %d\n",
           ntohs(icmp_header->id),
           ntohs(icmp_header->sqnum),
           (icmp_header->type),
           icmp_header->code);
    if (icmp_header->type == 8){
        reply_icmp(ip, icmp_header);
        write(tun_fd, buf, ntohs(ip->total_length));
        printf(" -> reply ICMP packet sent\n");
    }
}
u_int32_t seq_num = 100;
int send_syn = 0;
void handle_tcp(struct ipv4_header *ip, uint8_t *payload, int len,int tun_fd,uint8_t *buf) {
    printf("  -> TCP packet (not built yet, this is Week 4)\n");

    struct tcp_header *tcp_header = (struct tcp_header *) payload;

    printf(" -> tcp packet\n");
    debug_tcp_packet(tcp_header);


    if (compute_tcp_checksum(ip, tcp_header, tcp_header_len(tcp_header)==0)) {
        printf(" -> tcp checksum: OK\n");

        if (tcp_header->flags & (1<<1)){ // check if it is a SYN
            printf("HEADS UP GOT A SYNC PACKET\n");
            tcp_header->flags = (1<<1) | (1<<4);
            u_int16_t tmp_port = tcp_header->src_port;
            tcp_header->src_port = tcp_header->dest_port;
            tcp_header->dest_port = tmp_port;
            tcp_header->ack_num = htonl(ntohl(tcp_header->seq_num)+1);
            tcp_header->seq_num = htonl(seq_num ++);
            tcp_header->checksum = 0;
            tcp_header->checksum = compute_tcp_checksum(ip, tcp_header, ((tcp_header->data_offset_reserved&0xF0)>>4) *4);

            u_int32_t tmp_address = ip->src_ip;
            ip->src_ip = ip->dest_ip;
            ip->dest_ip = tmp_address;
            ip->checksum = 0;

            ip->checksum =  compute_checksum(ip, (ip->checksum&0x0f)*4);

            printf("-> REPLY TCP packet \n");
            debug_tcp_packet(tcp_header);
            send_syn = 1;
            write(tun_fd, buf, ntohs(ip->total_length));
        }
        if (tcp_header->flags &(1<<4)){ // check if it as ACK
            if (tcp_header->ack_num == seq_num){ // this is ACk for my SYN-ACK 
                printf("\t CONNECTION ESTABLISHED :) \n");
            }
        }
    } else {
        printf(" -> tcp checksum: INVALID \n");
    }
}
void handle_udp(struct ipv4_header *ip, uint8_t *payload, int len) {
    struct udp_header *udp = (struct udp_header *) payload;

    printf(" -> UDP packet\n");
    printf("\tSrc port : %d\n"
           "\tDst port : %d\n"
           "\tLength   : %d\n"
           "\tChecksum : 0x%04x\n",
           ntohs(udp->src_port),
           ntohs(udp->dst_port),
           ntohs(udp->length),
           ntohs(udp->checksum));

    uint16_t result = compute_udp_checksum(ip, udp, len);
    if (result == 0) {
        printf(" -> UDP checksum: OK\n");
    } else {
        printf(" -> UDP checksum: INVALID (result=0x%04x)\n", result);
    }
}
void classify_protocol(struct ipv4_header *ip, uint8_t *buf, int tun_fd) {
    int header_len = (ip->version_ihl & 0x0f) * 4;
    int payload_len = ntohs(ip->total_length) - header_len;
    uint8_t *payload = buf + header_len;
    switch (ip->protocol) {
        case IPPROTO_ICMP:
            handle_icmp(ip, buf, tun_fd);
            break;
        case IPPROTO_TCP:
            handle_tcp(ip,payload, payload_len,tun_fd,buf);
            break;
        case IPPROTO_UDP:
            handle_udp(ip, payload, payload_len);
            break;
        default:
            printf("  -> unknown protocol %d, dropping\n", ip->protocol);
    }
}
