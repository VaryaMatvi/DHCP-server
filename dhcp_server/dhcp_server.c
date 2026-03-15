#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
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

//keeped in BigEndian
struct Config{
    unsigned char subnet[4];
    unsigned char netmask[4];
    int lease_time;
    unsigned char dns_servers[MAX_DNS][4];
    int dns_count;
};

struct Config config;

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
        struct in_addr addr;
        if (key && value) {
            value[strcspn(value, "\r\n")] = '\0';
            if (strcmp(key, "subnet") == 0) 
            {
                inet_pton(AF_INET, value, &addr);
                memcpy(config.subnet, &addr.s_addr, 4);
            }
            else if (strcmp(key, "netmask") == 0)
            {
                inet_pton(AF_INET, value, &addr);
                memcpy(config.netmask, &addr.s_addr, 4);
            }
            else if (strcmp(key, "lease_time") == 0) config.lease_time = atoi(value);
            else if (strcmp(key, "dns_servers") == 0)
            {
                char *dns = strtok(value, ",");
                int n = 0;
                struct in_addr addr;

                while (dns && n < MAX_DNS) {
                    dns[strcspn(dns, "\r\n")] = '\0';
                    inet_pton(AF_INET, dns, &addr);
                    memcpy(config.dns_servers[n], &addr.s_addr, 4);
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
void dhcp_sender(unsigned char *buf, int buf_size, dhcp_fields *r)
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
    memcpy(buf+i, config.netmask, 4);
    i += 4;
    buf[i++] = 6; //dns
    buf[i++] = 4*config.dns_count;
    memcpy(buf+i, config.dns_servers, 4*config.dns_count);
    i += 4*config.dns_count;
    buf[i++] = 255; //end option
}


