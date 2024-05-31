#include <stdio.h>
#include <packet.h>

int main(int argc, char **argv)
{
    char *pinfo;
    size_t pinfo_size;
    struct packet pkt;

    printf("Enter packet info: ");
    getline(&pinfo, &pinfo_size, stdin);
    if (packet_parse(&pkt, pinfo)) {
        printf("FAILED\n");
    } else {
        printf("SUCCESS\n");
        printf("Source address: %d:%d\n", pkt.src, pkt.src_port);
        printf("Destination address: %d:%d\n", pkt.dst, pkt.dst_port);
        printf("Protocol: %s\n", pkt.proto == PROTO_TCP? "TCP" : "UDP");
    }

    return 0;
}
