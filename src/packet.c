#include <packet.h>

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

uint8_t packet_parse(struct packet *pkt, char *str)
{
    char *saveptr;
    char *lex = NULL;

    /* Parse source address */
    lex = strtok_r(str, " ", &saveptr);
    if (lex == NULL)
        return 1;

    inet_pton(AF_INET, lex, &pkt->src);
    pkt->src = ntohl(pkt->src);

    /* Parse destination address */
    lex = strtok_r(NULL, " ", &saveptr);
    if (lex == NULL)
        return 1;
    
    inet_pton(AF_INET, lex, &pkt->dst);
    pkt->dst = ntohl(pkt->dst);

    /* Parse source port */
    lex = strtok_r(NULL, " ", &saveptr);
    if (lex == NULL)
        return 1;
    
    if (!sscanf(lex, "%hd", &pkt->src_port))
        return 1;

    pkt->src_port = ntohs(pkt->src_port);

    /* Parse destination port */
    lex = strtok_r(NULL, " ", &saveptr);
    if (lex == NULL)
        return 1;
    
    if (!sscanf(lex, "%hd", &pkt->dst_port))
        return 1;

    pkt->dst_port = ntohs(pkt->dst_port);

    /* Parse protocol */
    lex = strtok_r(NULL, " ", &saveptr);
    if (lex == NULL)
        return 1;
    
    if (!sscanf(lex, "%d", &pkt->proto))
        return 1;

    return 0;
}
