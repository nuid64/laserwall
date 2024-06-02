#include <rule.h>

#include <stdint.h>

inline uint8_t match_addr(in_addr_t pat, in_addr_t addr, uint32_t mask)
{
    return (pat & mask) == (addr & mask);
}

uint8_t rule_packet_matching(struct rule *rule, struct packet *pkt)
{
    if ((rule->proto != PROTO_ANY) && (pkt->proto != rule->proto))
        return 0;
    
    if ((rule->src_port != PORT_ANY && pkt->src_port != rule->src_port)
     || (rule->dst_port != PORT_ANY && pkt->dst_port != rule->dst_port))
        return 0;

    if (!match_addr(rule->src, pkt->src, rule->src_mask)
     || !match_addr(rule->dst, pkt->dst, rule->dst_mask))
        return 0;

    return 1;
}
