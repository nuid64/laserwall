#include <stdint.h>
#include <netinet/in.h>
#include <packet.h>

#define PORT_ANY -1

typedef enum {
    VERDICT_ACCEPT,
    VERDICT_DROP,
} verdict;

struct rule {
    in_addr_t src;
    in_addr_t dst;
    uint32_t src_mask;
    uint32_t dst_mask;
    int32_t src_port;
    int32_t dst_port;
    protocol proto;
    verdict verdict;
};

uint8_t rule_packet_matching(struct rule *rule, struct packet *pkt);
