#pragma once

#include <rule.h>

#define IP_OCT_TO_NUM(a, b, c, d) \
    ( (((char)a) << 24) | (((char)b) << 16) | (((char)c) << 8)  | ((char)d) )

#define IP_STR_TO_NUM(s) \
    IP_OCT_TO_NUM( \
        (s[0] - '0') * 100 + (s[1] - '0') * 10 + (s[2] - '0'),    \
        (s[4] - '0') * 100 + (s[5] - '0') * 10 + (s[6] - '0'),    \
        (s[8] - '0') * 100 + (s[9] - '0') * 10 + (s[10] - '0'),   \
        (s[12] - '0') * 100 + (s[13] - '0') * 10 + (s[14] - '0') \
    )

#define FIREWALL_RULE(p_src, p_src_mask_bits, p_dst, p_dst_mask_bits, p_proto, p_verdict) \
    (struct rule )                                                                       \
    { .src = IP_STR_TO_NUM(p_src), .src_mask = (((uint32_t) 0xFFFFFFFF) << (32 - p_src_mask_bits)), \
      .dst = IP_STR_TO_NUM(p_dst), .dst_mask = (((uint32_t) 0xFFFFFFFF) << (32 - p_dst_mask_bits)), \
      .proto = p_proto, .verdict = p_verdict }

static struct rule ruleset[] = {
    FIREWALL_RULE("010.000.001.011", 32, "001.001.001.001", 32, PROTO_TCP, VERDICT_ACCEPT),
    FIREWALL_RULE("010.000.002.012", 32, "001.001.001.001", 32, PROTO_TCP, VERDICT_DROP),
    FIREWALL_RULE("010.000.002.012", 32, "008.008.008.008", 32, PROTO_TCP, VERDICT_ACCEPT),
    FIREWALL_RULE("010.000.003.013", 32, "000.000.000.000",  0, PROTO_ANY, VERDICT_ACCEPT),
    FIREWALL_RULE("000.000.000.000",  0, "001.002.003.004", 32, PROTO_UDP, VERDICT_DROP),
    FIREWALL_RULE("000.000.000.000",  0, "001.002.003.004", 32, PROTO_ANY, VERDICT_ACCEPT),
    FIREWALL_RULE("000.000.000.000",  0, "010.000.009.001", 32, PROTO_TCP, VERDICT_DROP),
    FIREWALL_RULE("010.000.005.000", 24, "000.000.000.000",  0, PROTO_ANY, VERDICT_ACCEPT),
};

static size_t ruleset_len = sizeof(ruleset) / sizeof(*ruleset);

verdict ruleset_packet_check(struct rule *ruleset, size_t ruleset_len, struct packet *pkt);
