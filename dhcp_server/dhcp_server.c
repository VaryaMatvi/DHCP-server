#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <hiredis/hiredis.h>

#define MAX_DNS 4

#define MAGICCOOKIE 0x63538263 
#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPACK 5


typedef struct {
    unsigned char xid[4]; //unique transaction id
    unsigned char yiaddr[4]; //new client ip
    unsigned char siaddr[4]; //servers ip
    unsigned char chaddr[16]; //client's MAC
    unsigned char msg_type;
}dhcp_fields;

struct Config{
    uint32_t subnet;
    uint32_t netmask;
    uint32_t lease_time;
    char dns_servers[MAX_DNS][4]; //keeped in BigEndian
    int dns_count;

    uint32_t ip;
};

struct Config config;
u_int16_t ID = 0; //servers global counter

//configuration setter
void load_config(const char *filename)
{
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("Config can't be opened.");
        exit(1);
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *key = strtok(line, ":");
        char *value = strtok(NULL, "\n");
        uint32_t addr;
        if (key && value) {
            value[strcspn(value, "\r\n")] = '\0';
            if (strcmp(key, "subnet") == 0) 
            {
                inet_pton(AF_INET, value, &addr);
                config.subnet = ntohl(addr);
            }
            else if (strcmp(key, "netmask") == 0)
            {
                inet_pton(AF_INET, value, &addr);
                config.netmask = ntohl(addr);     
            }
            else if (strcmp(key, "lease_time") == 0) config.lease_time = atoi(value);
            else if (strcmp(key, "dns_servers") == 0)
            {
                char *dns = strtok(value, ",");
                int n = 0;

                while (dns && n < MAX_DNS) {
                    dns[strcspn(dns, "\r\n")] = '\0';
                    inet_pton(AF_INET, dns, &addr);
                    memcpy(config.dns_servers[n], &addr, 4);
                    n++;
                    dns = strtok(NULL, ",");
                }
                config.dns_count = n;
            }
        }
    }
    fclose(f);
    printf("Configuration is loaded\n");
}

//processes data and returns mac and xid(unique transaction id) as a parameter
void dhcp_receiver(const unsigned char *buf, char* mac, dhcp_fields *r)
{
    const unsigned char *chaddr = buf + 28; //chaddr offset is 28 bytes, length=16
    memcpy(r->chaddr, chaddr, 16);
    //format for Redis
    sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5]);
    memcpy(r->xid, buf+4, 4); //xid offset is 4 bytes, length=4

    //seek type option
    uint32_t magic_cookie;
    memcpy(&magic_cookie, buf + 236, 4);
    int i = 240;
    if (magic_cookie == MAGICCOOKIE)
    {
        while (buf[i] != 255) //end option
        {
            if (buf[i] == 53) {
                r->msg_type = buf[i+2];
                break;
            }
            i += (buf[i+1] + 1); //len field
        }
    }
}

//forms a packet for the response and returns as the parameter buf
//returns new buf_size
int dhcp_sender(unsigned char *buf, int buf_size, dhcp_fields *r)
{
    int i=0; //byte counter
    memset(buf, 0, buf_size);

    //DHCP structure
    buf[i++] = 0x02; //op
    buf[i++] = 0x01; //htype
    buf[i++] = 0x06; //hlen for MAC
    i++; //zero hops
    memcpy(buf+i, r->xid, 4); //xid
    i += 4;
    i += 2; //zero secs
    i += 2; //zero flags
    i += 4; //zero ciaddr
    memcpy(buf+i, r->yiaddr, 4); //yiaddr
    i += 4;
    memcpy(buf+i, r->siaddr, 4); //siaddr
    i += 4;
    i += 4; //zero giaddr
    memcpy(buf+i, r->chaddr, 16); //chaddr
    i += 16;
    i += 64; //zero sname
    i += 128; //zero file

    unsigned int magic_cookie = MAGICCOOKIE;
    memcpy(buf+i, &magic_cookie, 4); //options
    i += 4;
    buf[i++] = 53; //msgtype
    buf[i++] = 1; //field len
    if (r->msg_type == DHCPDISCOVER) buf[i++] = DHCPOFFER;
    else if (r->msg_type == DHCPREQUEST) buf[i++] = DHCPACK;
    buf[i++] = 54; //DHCP ID
    buf[i++] = 4; //field len
    memcpy(buf+i, r->siaddr, 4);
    i += 4;

    uint32_t t = htonl(config.lease_time);
    buf[i++] = 51; //lease time
    buf[i++] = 4; //field len
    memcpy(buf+i,  &t, 4);
    i += 4;
    buf[i++] = 58; //rebinding time
    buf[i++] = 4;
    uint32_t t1 = htonl(config.lease_time / 2);
    memcpy(buf+i, &t1 , 4);
    i += 4;
    buf[i++] = 59; //renewing time
    buf[i++] = 4;
    uint32_t t2 = htonl(config.lease_time * 7 / 8);
    memcpy(buf+i, &t2, 4);
    i += 4;
    buf[i++] = 1; //mask
    buf[i++] = 4;
    uint32_t netmask = htonl(config.netmask);
    memcpy(buf+i, &netmask, 4);
    i += 4;
    buf[i++] = 6; //dns
    buf[i++] = 4*config.dns_count;
    memcpy(buf+i, config.dns_servers, 4*config.dns_count);
    i += 4*config.dns_count;
    buf[i++] = 255; //end option

    return i;
}

void packet_parser(unsigned char *data_buf, const unsigned char *packet_buf)
{
    //eth_header first 14 bytes
    unsigned char *ip_header = packet_buf + 14;
    if (((ip_header[0] & 0xF0) >> 4) != 4) return; //not IPv4
    if (ip_header[9] != 17) return; //not UDP
    uint32_t dest_addr;
    memcpy(&dest_addr, ip_header+16, 4);
    dest_addr = ntohl(dest_addr);
    

    uint32_t net_broadcast = (config.netmask & config.subnet) | (~config.netmask);
    if (dest_addr != config.ip && dest_addr != 0xFFFFFFFF && dest_addr != net_broadcast) return; //another ip

    unsigned int ihl = ip_header[0] & 0x0F; //ip header len in dwords
    unsigned char *udp_header = ip_header + ihl * 4;
    
    uint16_t source_port, dest_port;
    memcpy(&source_port, udp_header, 2);
    source_port = ntohs(source_port);
    memcpy(&dest_port, udp_header+2, 2);
    dest_port = ntohs(dest_port);
    if (source_port != 68 || dest_port != 67) return; //not DHCP

    uint16_t payload_length;
    memcpy(&payload_length, udp_header+4, 2);
    payload_length = ntohs(payload_length);
    payload_length -= 8; //minus udp_header length
    memcpy(data_buf, udp_header+8, payload_length);
    return;
}

//rebuilds the received packet (packet buf)
void packet_formater(const unsigned char *data_buf, int data_buf_size, unsigned char *packet_buf, dhcp_fields *fields)
{
    //Eth-header, 14 bytes
    //swaps source and dest macs 
    unsigned char temp_mac[6];
    memcpy(temp_mac, packet_buf, 6);
    memcpy(packet_buf, packet_buf+6, 6);
    memcpy(packet_buf+6, temp_mac, 6);

    //ip-header
    unsigned char *ip_header = packet_buf + 14;
    ip_header[0] = 0x45; //v4, IHL=5
    ip_header[1] = 0; //DSCP, ECN
    uint16_t ip_total_length = htons(20 + 8 + data_buf_size); //ip-header+udp-header+payload
    memcpy(ip_header+2, &ip_total_length, 2);
    uint16_t id = htons(ID);
    memcpy(ip_header+4, &id, 2);
    ID++;
    
    //flags+offset, DF=1, MF=0, offset=0
    ip_header[6] = 0x40;
    ip_header[7] = 0;
    ip_header[8] = 64; //TTL
    ip_header[9] = 17; //UDP
    memset(ip_header+10, 0, 2);//checksum
    
    memcpy(ip_header+12, fields->siaddr, 4);
    memcpy(ip_header+16, fields->yiaddr, 4);

    //udp-header
    unsigned char *udp_header = ip_header + 20;
    uint16_t source_port = htons(68), dest_port = htons(67);
    memcpy(udp_header, &source_port, 2);
    memcpy(udp_header+2, &dest_port, 2);
    uint16_t udp_length = htons(8 + data_buf_size);
    memcpy(udp_header+4, &udp_length, 2);
    memset(udp_header+6, 0, 2); //checksum

    memcpy(udp_header+8, data_buf, data_buf_size);
}
