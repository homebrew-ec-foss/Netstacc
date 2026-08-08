#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "../include/ipv4.h"
#include "../include/icmp.h"
#include "../include/udp.h"
#include "../include/tcp.h"
#include "../include/checksum.h"
#include "../include/classifier.h"

int icmp_rx_p = 0, icmp_rx_b = 0, icmp_tx_p = 0, icmp_tx_b = 0;
int udp_rx_p = 0, udp_rx_b = 0, udp_tx_p = 0, udp_tx_b = 0;
int tcp_rx_p = 0, tcp_rx_b = 0, tcp_tx_p = 0, tcp_tx_b = 0;
int tot_rx_p = 0, tot_rx_b = 0, tot_tx_p = 0, tot_tx_b = 0;

int non_ipv4_drops = 0;
int bad_checksums = 0;
int unknown_drops = 0;

char active_conn[64] = "Waiting for connection...";
char tcp_state[32] = "LISTEN";
uint32_t current_seq = 0;
uint32_t current_ack = 0;

char last_event[128] = "System initialized. Waiting for packets...";

void handle_icmp(struct ipv4_header *ip, uint8_t *buf, int tun_fd) {
    struct icmp_header* icmp_header = parse_icmp(buf, ip);
    if (icmp_header == NULL) return;

    int pkt_len = ntohs(ip->total_length);
    icmp_rx_p++;
    icmp_rx_b += pkt_len;

    snprintf(last_event, sizeof(last_event), "ICMP [Ping] Type: %d Code: %d", icmp_header->type, icmp_header->code);

    if (icmp_header->type == 8) {
        reply_icmp(ip, icmp_header);
        int tx_len = ntohs(ip->total_length);
        write(tun_fd, buf, tx_len);
        icmp_tx_p++;
        icmp_tx_b += tx_len;
    }
}

void handle_udp(struct ipv4_header *ip, uint8_t *payload, int len) {
    int pkt_len = ntohs(ip->total_length);
    udp_rx_p++;
    udp_rx_b += pkt_len;

    struct udp_header *udp = (struct udp_header *) payload;

    snprintf(last_event, sizeof(last_event), "UDP [Port %d -> %d] Len: %d bytes",
             ntohs(udp->src_port), ntohs(udp->dst_port), ntohs(udp->length));
}

void handle_tcp(struct ipv4_header *ip, uint8_t *payload, int len, int tun_fd, uint8_t *buf) {
    struct tcp_header *tcp_header = (struct tcp_header *) payload;

    int pkt_len = ntohs(ip->total_length);
    tcp_rx_p++;
    tcp_rx_b += pkt_len;

    if (verify_tcp_checksum(ip, tcp_header, len) == 0) {
        uint8_t *sip = (uint8_t *)&ip->src_ip;
        uint8_t *dip = (uint8_t *)&ip->dest_ip;
        
        snprintf(active_conn, sizeof(active_conn), "%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d", 
                 sip[0], sip[1], sip[2], sip[3], ntohs(tcp_header->src_port),
                 dip[0], dip[1], dip[2], dip[3], ntohs(tcp_header->dest_port));

        snprintf(last_event, sizeof(last_event), "TCP [Port %d -> %d] Flags: SYN:%d ACK:%d FIN:%d",
                 ntohs(tcp_header->src_port), ntohs(tcp_header->dest_port),
                 (tcp_header->flags & 2U) != 0,
                 (tcp_header->flags & 16U) != 0,
                 (tcp_header->flags & 1U) != 0);

        current_ack = ntohl(tcp_header->seq_num);

        if (tcp_header->flags == 2) { 
            strcpy(tcp_state, "SYN_RCVD");
            uint16_t tmp_port = tcp_header->src_port;
            tcp_header->src_port = tcp_header->dest_port;
            tcp_header->dest_port = tmp_port;
            tcp_header->flags = 18; 
            tcp_header->ack_num = htonl(ntohl(tcp_header->seq_num) + 1);
            tcp_header->seq_num = htonl(current_seq);

            int standard_tcp_hlen = sizeof(struct tcp_header);
            tcp_header->data_offset_reserved = (standard_tcp_hlen / 4) << 4;

            uint32_t tmp_ip = ip->src_ip;
            ip->src_ip = ip->dest_ip;
            ip->dest_ip = tmp_ip;

            int ip_hlen = (ip->version_ihl & 0x0f) * 4;
            int total_reply_len = ip_hlen + standard_tcp_hlen;
            
            ip->total_length = htons(total_reply_len);
            ip->checksum = 0;
            ip->checksum = compute_checksum((uint8_t *)ip, ip_hlen);

            tcp_header->checksum = 0;
            struct tcp_pseudo_header pseudo_syn;
            pseudo_syn.src_ip = ip->src_ip;
            pseudo_syn.dest_ip = ip->dest_ip;
            pseudo_syn.zero = 0;
            pseudo_syn.protocol = IPPROTO_TCP;
            pseudo_syn.tcp_length = htons(standard_tcp_hlen);

            uint8_t temp_buf[100];
            memcpy(temp_buf, &pseudo_syn, sizeof(pseudo_syn));
            memcpy(temp_buf + sizeof(pseudo_syn), tcp_header, standard_tcp_hlen);
            tcp_header->checksum = compute_checksum(temp_buf, sizeof(pseudo_syn) + standard_tcp_hlen);

            write(tun_fd, buf, total_reply_len);
            tcp_tx_p++;
            tcp_tx_b += total_reply_len;
            current_seq++;
        }
        else if (tcp_header->flags == 16) { 
            if (strcmp(tcp_state, "SYN_RCVD") == 0) {
                strcpy(tcp_state, "ESTABLISHED");
            }
        }
        
        int tcp_hlen = ((tcp_header->data_offset_reserved & 0xf0) >> 4) * 4;
        int tcp_data_len = len - tcp_hlen;

        if (tcp_data_len > 0) {
            uint8_t *payload_ptr = payload + tcp_hlen;
            if (strncmp((char *)payload_ptr, "GET ", 4) == 0) {
                char http_response[4096];
                char html_body[3000];

                tot_rx_p = icmp_rx_p + udp_rx_p + tcp_rx_p;
                tot_rx_b = icmp_rx_b + udp_rx_b + tcp_rx_b;
                tot_tx_p = icmp_tx_p + udp_tx_p + tcp_tx_p;
                tot_tx_b = icmp_tx_b + udp_tx_b + tcp_tx_b;

                int body_len = snprintf(html_body, sizeof(html_body),
"<html><head><meta http-equiv='refresh' content='2'>"
"<style>"
"body { background: #0d1117; color: #f0f6fc; font-family: monospace; padding: 20px; }"
"pre { font-family: monospace; font-size: 15px; line-height: 1.2; color: #d3869b; }"
"</style></head><body><pre>\n"
"  _   _      _   ____  _                   \n"
" | \\ | | ___| |_/ ___|| |_ __ _  ___ ___   \n"
" |  \\| |/ _ \\ __\\___ \\| __/ _` |/ __/ __|  \n"
" | |\\  |  __/ |_ ___) | || (_| | (_| (__   \n"
" |_| \\_|\\___|\\__|____/ \\__\\__,_|\\___\\___|  \n"
"----------------------------------------------------------------\n"
"Target Device: tun0 | Mode: Active | Telemetry: Live\n"
"----------------------------------------------------------------\n"
"PROTOCOL        RX PACKETS   RX BYTES    TX PACKETS   TX BYTES  \n"
"----------------------------------------------------------------\n"
"ICMP (Ping)     %-12d %-11d %-12d %-11d\n"
"UDP  (App)      %-12d %-11d %-12d %-11d\n"
"TCP  (Stack)    %-12d %-11d %-12d %-11d\n"
"----------------------------------------------------------------\n"
"TOTALS          %-12d %-11d %-12d %-11d\n"
"DROP DIAGNOSTICS\n"
"----------------------------------------------------------------\n"
"Non-IPv4 Traffic : %d\n"
"Bad Checksums    : %d\n"
"Unknown Protocols: %d\n"
"----------------------------------------------------------------\n"
"ACTIVE TCP CONNECTION\n"
"----------------------------------------------------------------\n"
"Target          : %s\n"
"State           : %s\n"
"Seq Number      : %u\n"
"Ack Number      : %u\n"
"Last Action     : HTTP 200 OK Response Sent\n"
"----------------------------------------------------------------\n"
"LATEST EVENT     : %s\n"
"</pre></body></html>",
                    icmp_rx_p, icmp_rx_b, icmp_tx_p, icmp_tx_b,
                    udp_rx_p, udp_rx_b, udp_tx_p, udp_tx_b,
                    tcp_rx_p, tcp_rx_b, tcp_tx_p, tcp_tx_b,
                    tot_rx_p, tot_rx_b, tot_tx_p, tot_tx_b,
                    non_ipv4_drops, bad_checksums, unknown_drops,
                    active_conn, tcp_state, current_seq, current_ack,
                    last_event);

                int response_len = snprintf(http_response, sizeof(http_response),
                    "HTTP/1.1 200 OK\r\n"
                    "Server: NetStacc/1.0\r\n"
                    "Content-Type: text/html\r\n"
                    "Content-Length: %d\r\n"
                    "Connection: close\r\n\r\n%s",
                    body_len, html_body);

                uint16_t tmp_port = tcp_header->src_port;
                tcp_header->src_port = tcp_header->dest_port;
                tcp_header->dest_port = tmp_port;
                tcp_header->flags = 24; 
                uint32_t browser_seq = ntohl(tcp_header->seq_num);
                tcp_header->ack_num = htonl(browser_seq + tcp_data_len);
                tcp_header->seq_num = htonl(current_seq);
                memcpy(payload_ptr, http_response, response_len);

                int total_reply_len = tcp_hlen + response_len;
                ip->total_length = htons(20 + total_reply_len);
                uint32_t tmp_ip = ip->src_ip;
                ip->src_ip = ip->dest_ip;
                ip->dest_ip = tmp_ip;
                int ip_hlen = (ip->version_ihl & 0x0f) * 4;
                ip->checksum = 0;
                ip->checksum = compute_checksum((uint8_t *)ip, ip_hlen);

                tcp_header->checksum = 0;
                struct tcp_pseudo_header pseudo_psh;
                pseudo_psh.src_ip = ip->src_ip;
                pseudo_psh.dest_ip = ip->dest_ip;
                pseudo_psh.zero = 0;
                pseudo_psh.protocol = IPPROTO_TCP;
                pseudo_psh.tcp_length = htons(total_reply_len);

                uint8_t *psh_buf = malloc(sizeof(pseudo_psh) + total_reply_len);
                memcpy(psh_buf, &pseudo_psh, sizeof(pseudo_psh));
                memcpy(psh_buf + sizeof(pseudo_psh), tcp_header, tcp_hlen);
                memcpy(psh_buf + sizeof(pseudo_psh) + tcp_hlen, payload_ptr, response_len);

                tcp_header->checksum = compute_checksum(psh_buf, sizeof(pseudo_psh) + total_reply_len);
                free(psh_buf);

                int tx_len = ntohs(ip->total_length);
                write(tun_fd, buf, tx_len);
                tcp_tx_p++;
                tcp_tx_b += tx_len;
                current_seq += response_len;
            }
        }
        else if (tcp_header->flags & 1) { 
            strcpy(tcp_state, "CLOSED");
            uint16_t tmp_port = tcp_header->src_port;
            tcp_header->src_port = tcp_header->dest_port;
            tcp_header->dest_port = tmp_port;
            tcp_header->flags = 20; 
            tcp_header->ack_num = htonl(ntohl(tcp_header->seq_num) + 1);
            tcp_header->seq_num = htonl(current_seq);
            uint32_t tmp_ip = ip->src_ip;
            ip->src_ip = ip->dest_ip;
            ip->dest_ip = tmp_ip;
            int ip_hlen = (ip->version_ihl & 0x0f) * 4;
            ip->total_length = htons(20 + 20); 
            ip->checksum = 0;
            ip->checksum = compute_checksum((uint8_t *)ip, ip_hlen);

            tcp_header->checksum = 0;
            struct tcp_pseudo_header pseudo_fin;
            pseudo_fin.src_ip = ip->src_ip;
            pseudo_fin.dest_ip = ip->dest_ip;
            pseudo_fin.zero = 0;
            pseudo_fin.protocol = IPPROTO_TCP;
            pseudo_fin.tcp_length = htons(20);

            uint8_t temp_buf[100];
            memcpy(temp_buf, &pseudo_fin, sizeof(pseudo_fin));
            memcpy(temp_buf + sizeof(pseudo_fin), tcp_header, 20);
            tcp_header->checksum = compute_checksum(temp_buf, sizeof(pseudo_fin) + 20);

            int tx_len = ntohs(ip->total_length);
            write(tun_fd, buf, tx_len);
            tcp_tx_p++;
            tcp_tx_b += tx_len;
        }
    }
}

void classify_protocol(struct ipv4_header *ip, uint8_t *buf, int tun_fd) {
    if ((ip->version_ihl >> 4) != 4) {
        non_ipv4_drops++;
        return;
    }

    int header_len = (ip->version_ihl & 0x0f) * 4;
    uint8_t *payload = buf + header_len;
    int payload_len = ntohs(ip->total_length) - header_len;

    switch (ip->protocol) {
        case IPPROTO_ICMP:
            handle_icmp(ip, buf, tun_fd);
            break;
        case IPPROTO_TCP:
            handle_tcp(ip, payload, payload_len, tun_fd, buf);
            break;
        case IPPROTO_UDP:
            handle_udp(ip, payload, payload_len);
            break;
        default:
            unknown_drops++;
            break;
    }
}
