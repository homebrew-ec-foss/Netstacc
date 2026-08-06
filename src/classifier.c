#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include "checksum.h"
#include "ipv4.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"
#include "classifier.h"

// --- NetStacc Telemetry Variables ---
int icmp_rx_p = 0, icmp_rx_b = 0, icmp_tx_p = 0, icmp_tx_b = 0;
int udp_rx_p = 0,  udp_rx_b = 0,  udp_tx_p = 0,  udp_tx_b = 0;
int tcp_rx_p = 0,  tcp_rx_b = 0,  tcp_tx_p = 0,  tcp_tx_b = 0;

char tcp_state[20] = "LISTEN";
char active_conn[64] = "Waiting for connection...";
uint32_t current_seq = 0;
uint32_t current_ack = 0;

u_int32_t seq_num = 100;
int send_syn = 0;

void handle_icmp(struct ipv4_header *ip, uint8_t *buf, int tun_fd) {
    struct icmp_header* icmp_header;
    if ((icmp_header = parse_icmp(buf,ip))==NULL) return;
    
    int pkt_len = ntohs(ip->total_length);
    icmp_rx_p++; 
    icmp_rx_b += pkt_len;

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
}

void handle_tcp(struct ipv4_header *ip, uint8_t *payload, int len, int tun_fd, uint8_t *buf) {
    struct tcp_header *tcp_header = (struct tcp_header *) payload;
    
    int pkt_len = ntohs(ip->total_length);
    tcp_rx_p++; 
    tcp_rx_b += pkt_len;

    if (verify_tcp_checksum(ip, tcp_header, len)) {
        
        uint8_t *sip = (uint8_t *)&ip->src_ip;
        uint8_t *dip = (uint8_t *)&ip->dest_ip;
        snprintf(active_conn, sizeof(active_conn), "%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d", 
                 sip[0], sip[1], sip[2], sip[3], ntohs(tcp_header->src_port),
                 dip[0], dip[1], dip[2], dip[3], ntohs(tcp_header->dest_port));

        current_ack = ntohl(tcp_header->seq_num);

        // --- 1. SYN HANDSHAKE ---
        if (tcp_header->flags & TCP_SYN) {
            strcpy(tcp_state, "SYN_RCVD");
            
            tcp_header->flags = TCP_SYN | TCP_ACK;
            
            u_int16_t tmp_port = tcp_header->src_port;
            tcp_header->src_port = tcp_header->dest_port;
            tcp_header->dest_port = tmp_port;
            
            tcp_header->ack_num = htonl(ntohl(tcp_header->seq_num) + 1);
            tcp_header->seq_num = htonl(seq_num++);
            tcp_header->checksum = 0;
            
            struct tcp_pseudo_header pseudo;
            pseudo.src_ip = ip->dest_ip;
            pseudo.dest_ip = ip->src_ip;
            pseudo.zero = 0;
            pseudo.protocol = IPPROTO_TCP;
            int tcp_hlen_bytes = ((tcp_header->data_offset_reserved & 0xF0) >> 4) * 4;
            pseudo.tcp_length = htons(tcp_hlen_bytes);
            
            uint8_t temp_buf[100]; 
            memcpy(temp_buf, &pseudo, sizeof(pseudo));
            memcpy(temp_buf + sizeof(pseudo), tcp_header, tcp_hlen_bytes);
            tcp_header->checksum = compute_checksum(temp_buf, sizeof(pseudo) + tcp_hlen_bytes);

            u_int32_t tmp_address = ip->src_ip;
            ip->src_ip = ip->dest_ip;
            ip->dest_ip = tmp_address;
            
            ip->checksum = 0;
            ip->checksum = compute_checksum(ip, (ip->version_ihl & 0x0f) * 4);
            
            int tx_len = ntohs(ip->total_length);
            write(tun_fd, buf, tx_len);
            tcp_tx_p++; 
            tcp_tx_b += tx_len;
            current_seq = seq_num;
        }
        
        // --- 2. ACK HANDSHAKE ---
        if (tcp_header->flags & TCP_ACK) { 
            if (ntohl(tcp_header->ack_num) == seq_num) {
                if (!(tcp_header->flags & TCP_SYN) && !(tcp_header->flags & TCP_FIN)) {
                    strcpy(tcp_state, "ESTABLISHED");
                }
            }
        }

        // --- 3. HTTP GET RESPONSE ---
        int tcp_hlen = tcp_header_len(tcp_header);
        int tcp_data_len = len - tcp_hlen;

        if ((tcp_header->flags & TCP_PSH) && (tcp_data_len > 0)) {
            uint8_t *payload_ptr = payload + tcp_hlen;

            if (strncmp((char*)payload_ptr, "GET ", 4) == 0) {
                char http_response[4096];
                char html_body[3000];

                int tot_rx_p = icmp_rx_p + udp_rx_p + tcp_rx_p;
                int tot_rx_b = icmp_rx_b + udp_rx_b + tcp_rx_b;
                int tot_tx_p = icmp_tx_p + udp_tx_p + tcp_tx_p;
                int tot_tx_b = icmp_tx_b + udp_tx_b + tcp_tx_b;

                int body_len = snprintf(html_body, sizeof(html_body),
                    "<html><head><meta http-equiv='refresh' content='2'>"
                    "<style>"
                    "body { background: #0d1117; color: #f0f6fc; font-family: monospace; padding: 20px; }"
                    "pre { font-family: monospace; font-size: 15px; line-height: 1.2; }"
                    "</style></head><body><pre>"
                    "  _   _  ZXRT34 _ ____  _                   \n"
                    " | \\ | | ___| |_/ ___|| |_ __ _  ___ ___  \n"
                    " |  \\| |/ _ \\ __\\___ \\| __/ _` |/ __/ __| \n"
                    " | |\\  |  __/ |_ ___) | || (_| | (_| (__  \n"
                    " |_| \\_|\\___|\\__|____/ \\__\\__,_|\\___\\___| \n"
                    "=========================================================\n"
                    " Target Device: tun0 | Mode: Active | Telemetry: Live\n"
                    "---------------------------------------------------------\n"
                    " PROTOCOL        RX PACKETS  RX BYTES  TX PACKETS  TX BYTES\n"
                    "---------------------------------------------------------\n"
                    " ICMP (Ping)     %-11d %-9d %-11d %-9d\n"
                    " UDP  (App)      %-11d %-9d %-11d %-9d\n"
                    " TCP  (Stack)    %-11d %-9d %-11d %-9d\n"
                    "---------------------------------------------------------\n"
                    " TOTALS          %-11d %-9d %-11d %-9d\n\n"
                    " DROP DIAGNOSTICS\n"
                    "---------------------------------------------------------\n"
                    " Non-IPv4 Traffic : 0\n"
                    " Bad Checksums    : 0\n"
                    " Unknown Protocols: 0\n\n"
                    " ACTIVE TCP CONNECTION\n"
                    "---------------------------------------------------------\n"
                    " Target        : %s\n"
                    " State         : %s\n"
                    " Seq Number    : %u\n"
                    " Ack Number    : %u\n"
                    " Last Action   : HTTP 200 OK Response Sent\n"
                    "</pre></body></html>",
                    icmp_rx_p, icmp_rx_b, icmp_tx_p, icmp_tx_b,
                    udp_rx_p, udp_rx_b, udp_tx_p, udp_tx_b,
                    tcp_rx_p, tcp_rx_b, tcp_tx_p, tcp_tx_b,
                    tot_rx_p, tot_rx_b, tot_tx_p, tot_tx_b,
                    active_conn, tcp_state, current_seq, current_ack);

                int response_len = snprintf(http_response, sizeof(http_response),
                    "HTTP/1.1 200 OK\r\n"
                    "Server: NetStacc/1.0\r\n"
                    "Content-Type: text/html\r\n"
                    "Content-Length: %d\r\n"
                    "Connection: close\r\n\r\n%s",
                    body_len, html_body);

                u_int16_t tmp_port = tcp_header->src_port;
                tcp_header->src_port = tcp_header->dest_port;
                tcp_header->dest_port = tmp_port;

                u_int32_t tmp_ip = ip->src_ip;
                ip->src_ip = ip->dest_ip;
                ip->dest_ip = tmp_ip;

                uint32_t browser_seq = ntohl(tcp_header->seq_num);
                tcp_header->seq_num = htonl(seq_num);
                tcp_header->ack_num = htonl(browser_seq + tcp_data_len);

                tcp_header->flags = TCP_PSH | TCP_ACK;
                memcpy(payload_ptr, http_response, response_len);

                int ip_hlen = (ip->version_ihl & 0x0f) * 4;
                ip->total_length = htons(ip_hlen + tcp_hlen + response_len);

                ip->checksum = 0;
                ip->checksum = compute_checksum(ip, ip_hlen);

                tcp_header->checksum = 0;
                struct tcp_pseudo_header pseudo_psh;
                pseudo_psh.src_ip = ip->src_ip;
                pseudo_psh.dest_ip = ip->dest_ip;
                pseudo_psh.zero = 0;
                pseudo_psh.protocol = IPPROTO_TCP;
                pseudo_psh.tcp_length = htons(tcp_hlen + response_len);
                
                int total_reply_len = sizeof(pseudo_psh) + tcp_hlen + response_len;
                uint8_t *psh_buf = malloc(total_reply_len);
                memcpy(psh_buf, &pseudo_psh, sizeof(pseudo_psh));
                memcpy(psh_buf + sizeof(pseudo_psh), tcp_header, tcp_hlen + response_len);
                tcp_header->checksum = compute_checksum(psh_buf, total_reply_len);
                free(psh_buf);

                int tx_len = ntohs(ip->total_length);
                write(tun_fd, buf, tx_len);
                tcp_tx_p++;
                tcp_tx_b += tx_len;
                seq_num += response_len;
                current_seq = seq_num;
            }
        }

        // --- 4. FIN TEARDOWN ---
        if (tcp_header->flags & TCP_FIN) { 
            strcpy(tcp_state, "CLOSED");
            
            u_int16_t tmp_port = tcp_header->src_port;
            tcp_header->src_port = tcp_header->dest_port;
            tcp_header->dest_port = tmp_port;

            u_int32_t tmp_ip = ip->src_ip;
            ip->src_ip = ip->dest_ip;
            ip->dest_ip = tmp_ip;

            tcp_header->ack_num = htonl(ntohl(tcp_header->seq_num) + 1);
            tcp_header->seq_num = htonl(seq_num);
            tcp_header->flags = TCP_FIN | TCP_ACK;

            int ip_hlen = (ip->version_ihl & 0x0f) * 4;
            ip->total_length = htons(ip_hlen + tcp_hlen);

            ip->checksum = 0;
            ip->checksum = compute_checksum(ip, ip_hlen);
            
            tcp_header->checksum = 0;
            struct tcp_pseudo_header pseudo_fin;
            pseudo_fin.src_ip = ip->src_ip;
            pseudo_fin.dest_ip = ip->dest_ip;
            pseudo_fin.zero = 0;
            pseudo_fin.protocol = IPPROTO_TCP;
            pseudo_fin.tcp_length = htons(tcp_hlen);
            
            uint8_t fin_buf[100];
            memcpy(fin_buf, &pseudo_fin, sizeof(pseudo_fin));
            memcpy(fin_buf + sizeof(pseudo_fin), tcp_header, tcp_hlen);
            tcp_header->checksum = compute_checksum(fin_buf, sizeof(pseudo_fin) + tcp_hlen);

            int tx_len = ntohs(ip->total_length);
            write(tun_fd, buf, tx_len);
            tcp_tx_p++; 
            tcp_tx_b += tx_len;
        }
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
            handle_tcp(ip, payload, payload_len, tun_fd, buf);
            break;
        case IPPROTO_UDP:
            handle_udp(ip, payload, payload_len);
            break;
    }
}
