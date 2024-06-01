#include <stdio.h>
#include <packet.h>
#include <ruleset.h>

int main(int argc, char **argv)
{
    char *pinfo;
    size_t pinfo_size;
    struct packet pkt;

    while (getline(&pinfo, &pinfo_size, stdin) != EOF) {
        packet_parse(&pkt, pinfo);

        if (ruleset_packet_check(ruleset, ruleset_len, &pkt) == VERDICT_ACCEPT)
            printf("ACCEPT\n");
        else
            printf("DROP\n");
    }

    return 0;
}
