#include <sys/types.h>

struct icmp_header{
    u_int8_t type;
    u_int8_t code;
    u_int16_t csum;
    u_int16_t id;
    u_int16_t sqnum;
}__attribute__((packed));

void reply_icmp(struct ipv4_header* ip_header,struct icmp_header* icmp_header);
struct icmp_header* parse_icmp(u_int8_t *buffer,struct ipv4_header* ip_header);
