#pragma once

#include <stdint.h>
#include <netinet/in.h>

typedef enum{
    PROTO_TCP = 6,
    PROTO_UDP = 17,
    PROTO_ANY,
} protocol;

struct packet {
    in_addr_t src;
    in_addr_t dst;
    uint16_t src_port;
    uint16_t dst_port;
    protocol proto;
};

uint8_t packet_parse(struct packet *pkt, char *str);
