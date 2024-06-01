#include <ruleset.h>

verdict ruleset_packet_check(struct rule *ruleset, size_t ruleset_len, struct packet *pkt)
{
    for (size_t i = 0; i < ruleset_len; ++i) {
        if (rule_packet_matching(&ruleset[i], pkt))
            return ruleset[i].verdict;
    }

    return VERDICT_DROP;
}
