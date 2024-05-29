#include <packet.h>

#include <stdio.h>
#include <string.h>

uint8_t packet_parse(struct packet *pkt, char *str)
{
    uint8_t *src_ptr = (uint8_t *) &pkt->src;
    uint8_t *dst_ptr = (uint8_t *) &pkt->dst;
    char *saveptr;
    char *lex = NULL;

    /* Parse source address */
    lex = strtok_r(str, " ", &saveptr);
    if (lex == NULL)
        return 1;

    if (sscanf(lex, "%hhd.%hhd.%hhd.%hhd", &src_ptr[0], &src_ptr[1], &src_ptr[2], &src_ptr[3]))
        return 1;

    /* Parse destination address */
    lex = strtok_r(NULL, " ", &saveptr);
    if (lex == NULL)
        return 1;
    
    if (sscanf(lex, "%hhd.%hhd.%hhd.%hhd", &dst_ptr[0], &dst_ptr[1], &dst_ptr[2], &dst_ptr[3]))
        return 1;

    /* Parse source port */
    lex = strtok_r(NULL, " ", &saveptr);
    if (lex == NULL)
        return 1;
    
    if (sscanf(lex, "%hd", &pkt->src_port))
        return 1;

    /* Parse destination port */
    lex = strtok_r(NULL, " ", &saveptr);
    if (lex == NULL)
        return 1;
    
    if (sscanf(lex, "%hd", &pkt->dst_port))
        return 1;

    /* Parse protocol */
    lex = strtok_r(NULL, " ", &saveptr);
    if (lex == NULL)
        return 1;
    
    if (sscanf(lex, "%d", &pkt->proto))
        return 1;

    return 0;
}
