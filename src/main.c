#include <stdlib.h>
#include <stdio.h>
#include <packet.h>
#include <ruleset.h>

int main(int argc, char **argv)
{
    char *pinfo;
    size_t pinfo_size;
    struct packet pkt;
    struct rule *ruleset = ruleset1;
    size_t ruleset_len = ruleset1_len;

    if (argc > 1) {
        uint8_t ruleset_num = atoi(argv[1]);
        if (ruleset_num == 2) {
            ruleset = ruleset2;
            ruleset_len = ruleset2_len;
        }
    }

    while (getline(&pinfo, &pinfo_size, stdin) != EOF) {
        packet_parse(&pkt, pinfo);

        if (ruleset_packet_check(ruleset, ruleset_len, &pkt) == VERDICT_ACCEPT)
            printf("ACCEPT\n");
        else
            printf("DROP\n");
    }

    return 0;
}
