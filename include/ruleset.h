#pragma once

#include <rule.h>

#define IP_OCT_TO_NUM(a, b, c, d) \
    ( (((char)a) << 24) | (((char)b) << 16) | (((char)c) << 8)  | ((char)d) )

#define IP_STR_TO_NUM(s) \
    IP_OCT_TO_NUM( \
        (s[0] - '0') * 100 + (s[1] - '0') * 10 + (s[2] - '0'),    \
        (s[4] - '0') * 100 + (s[5] - '0') * 10 + (s[6] - '0'),    \
        (s[8] - '0') * 100 + (s[9] - '0') * 10 + (s[10] - '0'),   \
        (s[12] - '0') * 100 + (s[13] - '0') * 10 + (s[14] - '0')  \
    )

#define FIREWALL_RULE(p_src, p_src_mask_bits, p_src_port, p_dst, p_dst_mask_bits, p_dst_port, p_proto, p_verdict) \
    (struct rule )                                                                                                \
    { .src = IP_STR_TO_NUM(p_src), .src_mask = (((uint32_t) 0xFFFFFFFF) << (32 - p_src_mask_bits)),               \
      .dst = IP_STR_TO_NUM(p_dst), .dst_mask = (((uint32_t) 0xFFFFFFFF) << (32 - p_dst_mask_bits)),               \
      .src_port = p_src_port, .dst_port = p_dst_port,                                                             \
      .proto = p_proto, .verdict = p_verdict }

static struct rule ruleset1[] = {
    FIREWALL_RULE("010.000.001.011", 32, PORT_ANY, "001.001.001.001", 32, PORT_ANY, PROTO_TCP, VERDICT_ACCEPT),
    FIREWALL_RULE("010.000.002.012", 32, PORT_ANY, "001.001.001.001", 32, PORT_ANY, PROTO_TCP, VERDICT_DROP),
    FIREWALL_RULE("010.000.002.012", 32, PORT_ANY, "008.008.008.008", 32, PORT_ANY, PROTO_TCP, VERDICT_ACCEPT),
    FIREWALL_RULE("010.000.003.013", 32, PORT_ANY, "000.000.000.000",  0, PORT_ANY, PROTO_ANY, VERDICT_ACCEPT),
    FIREWALL_RULE("000.000.000.000",  0, PORT_ANY, "001.002.003.004", 32, PORT_ANY, PROTO_UDP, VERDICT_DROP),
    FIREWALL_RULE("000.000.000.000",  0, PORT_ANY, "001.002.003.004", 32, PORT_ANY, PROTO_ANY, VERDICT_ACCEPT),
    FIREWALL_RULE("000.000.000.000",  0, PORT_ANY, "010.000.009.001", 32, PORT_ANY, PROTO_TCP, VERDICT_DROP),
    FIREWALL_RULE("010.000.005.000", 24, PORT_ANY, "000.000.000.000",  0, PORT_ANY, PROTO_ANY, VERDICT_ACCEPT),
};

static size_t ruleset1_len = sizeof(ruleset1) / sizeof(*ruleset1);

static struct rule ruleset2[] = {
    FIREWALL_RULE("010.000.001.011", 32, PORT_ANY, "001.001.001.001", 32, PORT_ANY, PROTO_QUIC, VERDICT_ACCEPT),
    FIREWALL_RULE("010.000.002.012", 32, PORT_ANY, "001.001.001.001", 32, PORT_ANY, PROTO_FTP, VERDICT_DROP),
    FIREWALL_RULE("010.000.002.012", 32, PORT_ANY, "008.008.008.008", 32,        1, PROTO_TCP, VERDICT_ACCEPT),
    FIREWALL_RULE("010.000.002.012", 32,    65535, "008.008.008.008", 32, PORT_ANY, PROTO_UDP, VERDICT_ACCEPT),
    FIREWALL_RULE("010.000.003.013", 32, PORT_ANY, "000.000.000.000",  0, PORT_ANY, PROTO_ANY, VERDICT_ACCEPT),
};

static size_t ruleset2_len = sizeof(ruleset2) / sizeof(*ruleset2);

verdict ruleset_packet_check(struct rule *ruleset, size_t ruleset_len, struct packet *pkt);
