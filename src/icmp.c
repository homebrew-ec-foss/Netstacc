#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include "../include/checksum.h"
#include "../include/ipv4.h"
#include "../include/icmp.h"

void reply_icmp(struct ipv4_header* ip_header,struct icmp_header* icmp_header){

    u_int32_t tmp_address = ip_header->src_ip;
    ip_header->src_ip = ip_header->dest_ip;
    ip_header->dest_ip = tmp_address;
    icmp_header->type=0;
    icmp_header->csum = 0;
    int ip_header_len = (ip_header->version_ihl&(0x0f))*4;

    icmp_header->csum = compute_checksum((void*)icmp_header, (ntohs(ip_header->total_length)-ip_header_len));

    ip_header->checksum= 0;
    ip_header->checksum= compute_checksum((void *)ip_header, ip_header_len);


}
struct icmp_header* parse_icmp(u_int8_t *buffer,struct ipv4_header* ip_header){
    int ip_header_len = (ip_header->version_ihl & 0x0f)*4;
    u_int8_t* icmp_data = buffer + ip_header_len;
    struct icmp_header* out = (struct icmp_header*)  icmp_data;
    if (compute_checksum(icmp_data,(ntohs(ip_header->total_length)-ip_header_len)) != 0 ){
        return NULL;
    }
    return out;
}


