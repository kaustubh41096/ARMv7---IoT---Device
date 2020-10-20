/*
 * dhcp.c
 *
 *  Created on: Mar 22, 2020
 *      Author: kaustubh
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "tm4c123gh6pm.h"
#include "eth0.h"
#include "gpio.h"
#include "spi0.h"
#include "uart0.h"
#include "wait.h"
#include "dhcp.h"
#include "timer.h"

#define RED_LED PORTF,1
#define BLUE_LED PORTF,2
#define GREEN_LED PORTF,3
#define PUSH_BUTTON PORTF,4

#define INIT 1
#define SELECTING 2
#define REQUESTING 3
#define BOUND 4
#define RENEWING 5
#define REBIND 6

#define SYN 0x02;
#define ACK 0x10;
#define PSH 0x08;
#define FIN 0x01;

#define MAX_PACKET_SIZE 1522

uint8_t data[MAX_PACKET_SIZE];

void initHw()
{
    // Configure HW to work with 16 MHz XTAL, PLL enabled, system clock of 40 MHz
    SYSCTL_RCC_R = SYSCTL_RCC_XTAL_16MHZ | SYSCTL_RCC_OSCSRC_MAIN
            | SYSCTL_RCC_USESYSDIV | (4 << SYSCTL_RCC_SYSDIV_S);

    // Enable clocks
    enablePort(PORTF);
    _delay_cycles(3);

    // Configure LED and pushbutton pins
    selectPinPushPullOutput(RED_LED);
    selectPinPushPullOutput(GREEN_LED);
    selectPinPushPullOutput(BLUE_LED);
    selectPinDigitalInput(PUSH_BUTTON);
}

void initEeprom()
{
    SYSCTL_RCGCEEPROM_R = 1;
    _delay_cycles(3);
    while (EEPROM_EEDONE_R & EEPROM_EEDONE_WORKING)
        ;
}

void writeEeprom(uint16_t add, uint32_t data)
{
    EEPROM_EEBLOCK_R = add >> 4;
    EEPROM_EEOFFSET_R = add & 0xF;
    EEPROM_EERDWR_R = data;
    while (EEPROM_EEDONE_R & EEPROM_EEDONE_WORKING)
        ;
}

uint32_t readEeprom(uint16_t add)
{
    EEPROM_EEBLOCK_R = add >> 4;
    EEPROM_EEOFFSET_R = add & 0xF;
    return EEPROM_EERDWR_R;
}

void displayConnectionInfo()
{
    uint8_t i;
    char str[10];
    uint8_t mac[6];
    uint8_t ip[4];
    etherGetMacAddress(mac);
    putsUart0("HW: ");
    for (i = 0; i < 6; i++)
    {
        sprintf(str, "%02x", mac[i]);
        putsUart0(str);
        if (i < 6 - 1)
            putcUart0(':');
    }
    putcUart0('\n');
    etherGetIpAddress(ip);
    putsUart0("IP: ");
    for (i = 0; i < 4; i++)
    {
        sprintf(str, "%u", ip[i]);
        putsUart0(str);
        if (i < 4 - 1)
            putcUart0('.');
    }
    if (etherIsDhcpEnabled())
        putsUart0(" (dhcp)");
    else
        putsUart0(" (static)");
    putcUart0('\n');
    etherGetIpSubnetMask(ip);
    putsUart0("SN: ");
    for (i = 0; i < 4; i++)
    {
        sprintf(str, "%u", ip[i]);
        putsUart0(str);
        if (i < 4 - 1)
            putcUart0('.');
    }
    putcUart0('\n');
    etherGetIpGatewayAddress(ip);
    putsUart0("GW: ");
    for (i = 0; i < 4; i++)
    {
        sprintf(str, "%u", ip[i]);
        putsUart0(str);
        if (i < 4 - 1)
            putcUart0('.');
    }
    putcUart0('\n');
    if (etherIsLinkUp())
        putsUart0("Link is up\n");
    else
        putsUart0("Link is down\n");
}

uint16_t searchDhcpOptions(uint8_t packet[], uint8_t val)
{
    etherFrame* ether = (etherFrame*) packet;
    ipFrame* ip = (ipFrame*) &ether->data;
    udpFrame* udp = (udpFrame*) ((uint8_t*) ip + ((ip->revSize & 0xF) * 4));
    dhcpFrame* dhcp = (dhcpFrame*) &udp->data;
    uint16_t i;
    for (i = 0; i < 312; i = i + dhcp->options[i + 1] + 2)
    {
        if (dhcp->options[i] == val)
        {
            return i;
        }
    }
    return 450;
}

bool etherIsTcp(uint8_t packet[])
{
    etherFrame* ether = (etherFrame*) packet;
    ipFrame* ip = (ipFrame*) &ether->data;
    tcpFrame* tcp = (tcpFrame*) ((uint8_t*) ip + ((ip->revSize & 0xF) * 4));
    bool ok;
    uint16_t tmp16;
    ok = (ip->protocol == 6);
    /*if (ok)
     {
     sum = 0;
     etherSumWords(ip->sourceIp, 8);
     tmp16 = ip->protocol;
     sum += (tmp16 & 0xff) << 8;
     etherSumWords(&tcp->length, 2);
     // add tcp header and data
     etherSumWords(tcp, tcp->length);
     ok = (getEtherChecksum() == 0);
     }*/
    return ok;
}

bool etherIsTcpSyn(uint8_t packet[])
{
    etherFrame* ether = (etherFrame*) packet;
    ipFrame* ip = (ipFrame*) &ether->data;
    tcpFrame* tcp = (tcpFrame*) ((uint8_t*) ip + ((ip->revSize & 0xF) * 4));
    if (tcp->flags == 0b00000010)
    {
        return true;
    }
    else
    {
        return false;
    }

}

void sendEtherTcpSynAck(uint8_t packet[])
{
    uint16_t tmp16;
    uint8_t tmpip[4];
    uint8_t tmpmac[6];
    uint16_t tcplength;
    etherFrame* ether = (etherFrame*) packet;
    ipFrame* ip = (ipFrame*) &ether->data;
    tcpFrame* tcp = (tcpFrame*) ((uint8_t*) ip + (ip->revSize & 0xF) * 4);
    tmp16 = tcp->destp;
    tcp->destp = tcp->srcp;
    tcp->srcp = tmp16;
    tcp->ack = htonl(htonl(tcp->seq) + 1);
    tcp->seq = 0;
    tcp->off = 5;
    tcp->res = 0;
    tcp->flags = 0b00010010;
    tcp->winsize = htons(1280);
    tcp->urgptr = 0;
    memcpy(&tmpip, &ip->sourceIp, 4);
    memcpy(&ip->sourceIp, &ip->destIp, 4);
    memcpy(&ip->destIp, &tmpip, 4);
    //ip->headerChecksum = 0;
    memcpy(&tmpmac, &ether->sourceAddress, 6);
    memcpy(&ether->sourceAddress, &ether->destAddress, 6);
    memcpy(&ether->destAddress, &tmpmac, 6);
    ip->length = htons(((ip->revSize & 0xF) * 4) + 20);
    // 32-bit sum over ip header
    sum = 0;
    etherSumWords(&ip->revSize, 10);
    etherSumWords(ip->sourceIp, ((ip->revSize & 0xF) * 4) - 12);
    ip->headerChecksum = getEtherChecksum();
    tcplength = 20;
    // 32-bit sum over pseudo-header
    sum = 0;
    etherSumWords(ip->sourceIp, 8);
    tmp16 = ip->protocol;
    sum += (tmp16 & 0xff) << 8;
    etherSumWords(&tcplength, 2);
    etherSumWords(tcp, 20);
    tcp->checksum = getEtherChecksum();
    etherPutPacket(ether, 14 + ((ip->revSize & 0xF) * 4) + 20);

}

bool etherIsDhcp(uint8_t packet[])
{
    etherFrame* ether = (etherFrame*) packet;
    ipFrame* ip = (ipFrame*) &ether->data;
    udpFrame* udp = (udpFrame*) ((uint8_t*) ip + ((ip->revSize & 0xF) * 4));
    dhcpFrame* dhcp = (dhcpFrame*) &udp->data;
    if (ip->protocol == 17 && htons(udp->destPort) == 68
            && dhcpsm.xid == dhcp->xid)
    {
        return true;
    }
    else
    {
        return false;
    }
}

bool etherIsDhcpOffer(uint8_t packet[])
{
    etherFrame* ether = (etherFrame*) packet;
    ipFrame* ip = (ipFrame*) &ether->data;
    udpFrame* udp = (udpFrame*) ((uint8_t*) ip + ((ip->revSize & 0xF) * 4));
    dhcpFrame* dhcp = (dhcpFrame*) &udp->data;
    if (dhcp->options[2] == 2)
    {
        return true;
    }
    else
    {
        return false;
    }
}

bool etherIsDhcpAck(uint8_t packet[])
{
    etherFrame* ether = (etherFrame*) packet;
    ipFrame* ip = (ipFrame*) &ether->data;
    udpFrame* udp = (udpFrame*) ((uint8_t*) ip + ((ip->revSize & 0xF) * 4));
    dhcpFrame* dhcp = (dhcpFrame*) &udp->data;
    if (dhcp->options[2] == 5)
    {
        return true;
    }
    else
    {
        return false;
    }
}

void setDhcpAddresses(uint8_t packet[], uint8_t type)
{
    etherFrame* ether = (etherFrame*) packet;
    ipFrame* ip = (ipFrame*) &ether->data;
    udpFrame* udp = (udpFrame*) ((uint8_t*) ip + ((ip->revSize & 0xF) * 4));
    dhcpFrame* dhcp = (dhcpFrame*) &udp->data;
    uint16_t siaddrval = searchDhcpOptions(packet, 54);
    uint16_t giaddrval = searchDhcpOptions(packet, 3);
    if (siaddrval != 450 && giaddrval != 450)
    {
        memcpy(&dhcpsm.siaddr, &dhcp->options[siaddrval + 2], 4);
        memcpy(&dhcpsm.giadder, &dhcp->options[giaddrval + 2], 4);
        memcpy(&dhcpsm.yiaddr, &dhcp->yiaddr, 4);
        if (type == 5)
        {
            memcpy(&dhcpsm.ciaddr, &dhcp->yiaddr, 4);
            etherSetIpAddress(dhcp->yiaddr[0], dhcp->yiaddr[1], dhcp->yiaddr[2],
                              dhcp->yiaddr[3]);
        }
    }
    else
    {
        //Error in recieving
        setPinValue(RED_LED, 1);
        waitMicrosecond(1000000);
        setPinValue(RED_LED, 0);
        waitMicrosecond(100000);
    }
}

void etherSetDhcpTimers(uint8_t packet[])
{
    etherFrame* ether = (etherFrame*) packet;
    ipFrame* ip = (ipFrame*) &ether->data;
    udpFrame* udp = (udpFrame*) ((uint8_t*) ip + ((ip->revSize & 0xF) * 4));
    dhcpFrame* dhcp = (dhcpFrame*) &udp->data;
    uint16_t t1ind = searchDhcpOptions(packet, 58);
    dhcpsm.t1 = (dhcp->options[t1ind + dhcp->options[t1ind + 1] + 1]) / 2;
    dhcpsm.t2 = 7 * (dhcp->options[t1ind + dhcp->options[t1ind + 1] + 1]) / 8;
}

void main()

{
    uint8_t data2[MAX_PACKET_SIZE];
    //uint8_t arp[MAX_PACKET_SIZE];
    uint8_t* udpData;
    USER_DATA usrdata;
    uint8_t i;
    // uint32_t ip[4] = {192, 168, 0, 132};
    uint32_t test = 1;
    // uint32_t num[4] = {0,0,0,0};
    //char* token;
    //uint8_t v[6];
    //uint8_t cnt = 0;
    // Init controller
    initHw();
    initTimer();
    initEeprom();

    writeEeprom(0x0001, test);

    // Setup UART0
    initUart0();
    setUart0BaudRate(115200, 40e6);

    // Init ethernet interface (eth0)
    putsUart0("\nStarting eth0\n");
    etherInit(ETHER_UNICAST | ETHER_BROADCAST | ETHER_HALFDUPLEX);
    displayConnectionInfo();

    // Flash LED
    setPinValue(GREEN_LED, 1);
    waitMicrosecond(100000);
    setPinValue(GREEN_LED, 0);
    waitMicrosecond(100000);
    dhcpsm.state = INIT;
    startPeriodicTimer(discoverMessage, 15);
    sendDhcpMessage(data, 1);
    while (true)
    {
        if (kbhitUart0())
        {
            getsUart0(&usrdata);
            ParseFields (&usrdata);
            if (strcmp(usrdata.command, "ifconfig"))
            {
                displayConnectionInfo();
            }
            if (strcmp(usrdata.command, "dhcp"))
            {
                if (strcmp(usrdata.parameter, "release"))
                {
                    if (dhcpsm.state == BOUND)
                    {
                        //sendDhcpMessage(data, 7);
                    }
                }
                if (strcmp(usrdata.parameter, "renew"))
                {
                    if (dhcpsm.state == BOUND)
                    {
                        //sendDhcpMessage(data, 3);
                    }
                }
                if(strcmp(usrdata.parameter, "on"))
                {
                    etherEnableDhcpMode();
                }
                if(strcmp(usrdata.parameter, "off"))
                {
                    etherDisableDhcpMode();
                }
            }
            if (strcmp(usrdata.command, "setip"))
            {
                for (i = 0; usrdata.parameter[i] != '\0'; i++)
                {
                    if(usrdata.parameter[i] != ".")
                        ipAddress[i] = usrdata.parameter[i];
                }
            }
            if (strcmp(usrdata.command, "setgw"))
            {
                for (i = 0; usrdata.parameter[i] != '\0'; i++)
                {
                    if(usrdata.parameter[i] != ".")
                        ipGwAddress[i] = usrdata.parameter[i];
                }
            }
            if (strcmp(usrdata.command, "setsn"))
            {
                for (i = 0; usrdata.parameter[i] != '\0'; i++)
                {
                    if(usrdata.parameter[i] != ".")
                        ipSubnetMask[i] = usrdata.parameter[i];
                }
            }
        }

        if (etherIsDataAvailable())
        {
            if (etherIsOverflow())
            {
                setPinValue(RED_LED, 1);
                waitMicrosecond(100000);
                setPinValue(RED_LED, 0);
            }

            etherGetPacket(data, MAX_PACKET_SIZE);
            if (etherIsArpRequest(data))
            {
                etherSendArpResponse(data);
            }
            if (etherIsIp(data))
            {
                if (etherIsIpUnicast(data))
                {
                    // handle icmp ping request
                    if (etherIsPingRequest(data))
                    {
                        etherSendPingResponse(data);
                    }
                }
            }
             if (etherIsDhcp(data))
             {
             if (etherIsDhcpOffer(data))
             {
             stopTimer(discoverMessage);
             //waitMicrosecond(400000);
             dhcpsm.state = SELECTING;
             setPinValue(BLUE_LED, 1);
             waitMicrosecond(100000);
             setPinValue(BLUE_LED, 0);
             setDhcpAddresses(data, 1);
             sendDhcpMessage(data, 3);
             dhcpsm.state = REQUESTING;
             }
             if (etherIsDhcpAck(data))
             {
             dhcpsm.state = BOUND;
             setPinValue(GREEN_LED, 1);
             waitMicrosecond(100000);
             setPinValue(GREEN_LED, 0);
             //startPeriodicTimer(renewState, dhcpsm.t1);
             //startPeriodicTimer(rebindState, dhcpsm.t2);
             setDhcpAddresses(data, 5);
             // etherSendArpRequest(arp, dhcpsm.siaddr);
             }
             }
             if (etherIsTcp(data))
             {
             if (etherIsTcpSyn(data))
             {
             sendEtherTcpSynAck(data);
             }

             }
        }
    }
}
