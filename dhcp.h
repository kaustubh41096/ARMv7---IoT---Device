/*
 * dhcp.h
 *
 *  Created on: Mar 22, 2020
 *      Author: kaustubh
 */

#ifndef DHCP_H_
#define DHCP_H_
#define MAX_PACKET_SIZE 1522

extern uint8_t data[MAX_PACKET_SIZE];

typedef struct _dhcpstatemachine
{
    uint8_t state;
    uint32_t xid;
    uint8_t siaddr[4];
    uint8_t giadder[4];
    uint8_t yiaddr[4];
    uint8_t ciaddr[4];
    uint32_t t1;
    uint32_t t2;

}dhcpstatemachine;

extern dhcpstatemachine dhcpsm;

bool etherIsDhcpAck(uint8_t packet[]);

#endif /* DHCP_H_ */
