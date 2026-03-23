#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <hiredis/hiredis.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>

#define ETH_NAME "veth0" //listening interface name
#define HASH "dhcp:mappings" //Redis hash
#define VLEN 4 //max count of messages for a socket
#define MAX_PACKET_SIZE 1024
#define MAX_DHCP 576
#define MAX_RING_BUF_SIZE 32    //max requests in the ring buffer
#define RING_BUF_TRIGGER_COUNT 16 //start processing
#define RING_BUF_TIMEOUT 3 //ring buffer timeout in secs

#define MAX_DNS 4

#define MAGICCOOKIE 0x63825363 
#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPACK 5
#define DHCPERR "err"


//keeped in BE
typedef struct {
    unsigned char xid[4]; //unique transaction id
    unsigned char yiaddr[4]; //new client ip
    unsigned char siaddr[4]; //servers ip
    unsigned char chaddr[16]; //client's MAC
    unsigned char msg_type; //client's msg type
}dhcp_fields;

typedef unsigned char mac[18];
typedef struct{
    mac requests[MAX_RING_BUF_SIZE]; //keeps MACs for the Redis
    int head;
    int tail;
    int count;
    struct timespec last_p_time;
}ring_buffer;

struct Config{
    uint32_t subnet;
    uint32_t netmask;
    uint32_t lease_time;
    unsigned char dns_servers[MAX_DNS][4]; //keeped in BigEndian
    int dns_count;

    uint32_t ip;
    unsigned char mac[6];
};

struct Config config;
u_int16_t ID = 0; //servers global counter
int g_if_index = 0; //global if index

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
int dhcp_receiver(const unsigned char *buf, char* mac, dhcp_fields *r)
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
    if (ntohl(magic_cookie) != MAGICCOOKIE) return -1;
    while (buf[i] != 255) //end option
    {
        if (buf[i] == 53) {
             r->msg_type = buf[i+2];
            break;
        }
        i += (buf[i+1] + 2); //len field
    }
    if (r -> msg_type != DHCPDISCOVER && r -> msg_type != DHCPREQUEST) return -1;
    return 0;
}

//forms a packet for the response and returns as the parameter buf
//returns new buf_size
int dhcp_sender(unsigned char *buf, dhcp_fields *r)
{
    int i=0; //byte counter
    memset(buf, 0, MAX_DHCP);

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

    unsigned int magic_cookie = htonl(MAGICCOOKIE);
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

//returns payload_length
int packet_parser(unsigned char *data_buf, const unsigned char *packet_buf)
{
    //skip eth_header first 14 bytes
    //ip_header parsing
    unsigned char *ip_header = packet_buf + 14;
    if (((ip_header[0] & 0xF0) >> 4) != 4) return -1; //not IPv4
    if (ip_header[9] != 17) return -1; //not UDP
    uint32_t dest_addr;
    memcpy(&dest_addr, ip_header+16, 4);
    dest_addr = ntohl(dest_addr);
    

    uint32_t net_broadcast = (config.netmask & config.subnet) | (~config.netmask);
    if (dest_addr != config.ip && dest_addr != 0xFFFFFFFF && dest_addr != net_broadcast) return -1; //another ip

    unsigned int ihl = ip_header[0] & 0x0F; //ip-header len in dwords

    //udp-header parcing
    unsigned char *udp_header = ip_header + ihl * 4;
    uint16_t source_port, dest_port;
    memcpy(&source_port, udp_header, 2);
    source_port = ntohs(source_port);
    memcpy(&dest_port, udp_header+2, 2);
    dest_port = ntohs(dest_port);
    if (source_port != 68 || dest_port != 67) return -1; //not DHCP

    uint16_t payload_length;
    memcpy(&payload_length, udp_header+4, 2);
    payload_length = ntohs(payload_length);
    payload_length -= 8; //minus udp_header length

    if (payload_length > MAX_DHCP) return -1;
    memcpy(data_buf, udp_header+8, payload_length);
    return payload_length;
}

//cheksums for testing
uint16_t ip_checksum(void *vdata, size_t length) {
    char *data = (char *)vdata;
    uint32_t acc = 0xffff;
    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff) acc -= 0xffff;
    }
    if (length & 1) {
        uint16_t word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff) acc -= 0xffff;
    }
    return htons(~acc);
}

uint16_t udp_checksum(const char *ip_source, const char *ip_dest, const char *udp, uint16_t udp_length)
{
    unsigned char ip_pseudo[12];
    memcpy(ip_pseudo, ip_source, 4); 
    memcpy(ip_pseudo+4, ip_dest, 4);
    ip_pseudo[8] = 0; //0
    ip_pseudo[9] = 17; //protocol (UDP)
    uint16_t udp_length_n = htons(udp_length);
    memcpy(ip_pseudo+10, &udp_length_n, 2); //udp_length

    uint32_t acc = 0;
    uint16_t word;

    for (int i=0; i<12; i+=2) //always even
    {
        word = 0;
        memcpy(&word, ip_pseudo + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff) acc = (acc & 0xffff) + 1; //end-around carry
    }

    for (int i=0; i < udp_length - 1; i+=2) //UDP + payload (except last byte)
    {
        word = 0;
        memcpy(&word, udp+i, 2);
        acc += ntohs(word);
        if (acc > 0xffff) acc = (acc & 0xffff) + 1; //end-around carry
    }

    if (udp_length & 1) //check if odd
    {
        word = 0;
        memcpy(&word, udp + udp_length - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff) acc = (acc & 0xffff) + 1; //end-around carry
    }

    return htons(~acc);
}

//builds the packet to answer (packet buf_ans), returns total len
int packet_formater(const unsigned char *data_buf, int data_buf_size, unsigned char *packet_buf_ans, dhcp_fields *fields)
{
    //Eth-header, 14 bytes
    memcpy(packet_buf_ans, fields->chaddr, 6); //dest mac (client)
    memcpy(packet_buf_ans+6, config.mac, 6); //source mac (server)
    packet_buf_ans[12] = 0x08; //ipv4
    packet_buf_ans[13] = 0;

    //ip-header
    unsigned char *ip_header = packet_buf_ans + 14;
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
    
    uint32_t ip = htonl(config.ip);
    memcpy(ip_header+12, &ip, 4); //ip source
    //ip dest
    if (fields->msg_type == DHCPDISCOVER) memset(ip_header+16, 0xFF, 4);
    else if (fields -> msg_type == DHCPREQUEST) memcpy(ip_header+16, fields->yiaddr, 4); 

    uint16_t ip_csum = ip_checksum(ip_header, 20);
    memcpy(ip_header+10, &ip_csum, 2);

    //udp-header
    unsigned char *udp_header = ip_header + 20;
    uint16_t source_port = htons(67), dest_port = htons(68);
    memcpy(udp_header, &source_port, 2);
    memcpy(udp_header+2, &dest_port, 2);
    uint16_t udp_length = htons(8 + data_buf_size);
    memcpy(udp_header+4, &udp_length, 2);
    memset(udp_header+6, 0, 2); //zero checksum

    memcpy(udp_header+8, data_buf, data_buf_size);

    uint16_t udp_chsum = udp_checksum(ip_header + 12, ip_header + 16, udp_header, data_buf_size + 8);
    memcpy(udp_header + 6, &udp_chsum, 2);

    return 14 + 20 + 8 + data_buf_size; //ethernet + ip + udp + payload
}

//pipeline processing of the Redis requests, send answers
int rb_process(ring_buffer *rb, redisContext *ctx, dhcp_fields *requests, int sockfd, struct sockaddr_ll dest_addr)
{
    //save count and head for requests
    int n = rb->count;
    int head = rb -> head;
    int head_append = rb -> head;

    unsigned char answer_data_buf[MAX_DHCP];
    unsigned char answer_buf[MAX_PACKET_SIZE];
    int answer_data_len, total_len;

    if (n == 0)
    {
        return 0;
    }
    for (int i=0; i<n; i++)
    {
        redisAppendCommand(ctx, "HGET %s %s", HASH, rb->requests[head_append]);
        rb->count--;
        head_append = (head_append + 1) % MAX_RING_BUF_SIZE;
    }
    
    for (int i=0; i<n; i++)
    {
        redisReply *r;
        redisGetReply(ctx, (void**)&r);
        if (r != NULL && r->type == REDIS_REPLY_STRING) //got ip
        {

            printf("Got IP: %s\n", r->str);
            uint32_t client_ip;
            inet_pton(AF_INET, r->str, &client_ip);
            memcpy(requests[head].yiaddr, &client_ip, sizeof(client_ip)); 

            uint32_t s_ip = htonl(config.ip);
            memcpy(requests[head].siaddr, &s_ip, 4);

            answer_data_len = dhcp_sender(answer_data_buf, &requests[head]);
            total_len = packet_formater(answer_data_buf, answer_data_len, answer_buf, &requests[head]);

            //dest_addr structure for the sendto
            memcpy(dest_addr.sll_addr, requests[head].chaddr, 6); //dest mac
            dest_addr.sll_ifindex = g_if_index; //if index

            printf("sending answer\n");
            ssize_t sent = sendto(sockfd, answer_buf, total_len, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
            if (sent != total_len) {
                perror("sendto");
            } else {
                printf("Sent %d bytes\n", sent);
            }
        }
        else if (r -> type == REDIS_REPLY_NIL)
        {
            printf("MAC is not found\n");
        }
        freeReplyObject(r);

        head = (head + 1) % MAX_RING_BUF_SIZE;
    }

    rb -> count = 0;
    rb -> head = head;
    rb -> tail = rb -> head;
    clock_gettime(CLOCK_MONOTONIC, &rb->last_p_time);
    return 0;
}

int new_rb_record(ring_buffer *rb)
{
    rb->count++;
    rb->tail = (rb->tail + 1) % MAX_RING_BUF_SIZE;
    if (rb->count == MAX_RING_BUF_SIZE)
    {
        printf("Buffer is full\n");
        return 1;
    }
    return 0;
}

int main()
{
    load_config("dhcp_config.txt");

    redisContext *ctx = redisConnect("127.0.0.1", 6379); //connect localhost Redis
    if (ctx == NULL || ctx -> err){
        if (ctx){
            printf("Error %s\n", ctx->errstr);
            redisFree(ctx);
        }
        exit(1);
    }

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));

    struct sockaddr_ll server;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ETH_NAME, sizeof(ETH_NAME));
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl SIOCGIFINDEX");
        exit(1);
    }

    server.sll_ifindex = ifr.ifr_ifindex;
    printf("Server index set %d\n", server.sll_ifindex);
    g_if_index = ifr.ifr_ifindex;

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) //gets interface ip addr
    {
        perror("ioctl SIOCGIFADDR");
        exit(1);
    }
    struct sockaddr_in* addr_in = (struct sockaddr_in*)&ifr.ifr_addr;
    config.ip = ntohl(addr_in->sin_addr.s_addr); //sets server's ip

    if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) //gets interface mac addr
    {
        perror("ioctl SIOCGiFHWADDR");
        exit(1);
    }
    unsigned char *ifr_mac = (unsigned char *) ifr.ifr_hwaddr.sa_data;
    memcpy(config.mac, ifr_mac, 6); //sets server's mac

    //setting addr params
    memset(&server, 0, sizeof(server)); 
    server.sll_family = AF_PACKET;
    server.sll_protocol = htons(ETH_P_IP);
    server.sll_halen = ETH_ALEN;

    if (bind(sockfd, (struct sockaddr *)&server, sizeof(server)) == -1) {
        perror("bind");
        exit(1);
    }

    struct mmsghdr msgvec[VLEN];
    struct iovec iovecs[VLEN];
    unsigned char bufs[VLEN][MAX_PACKET_SIZE];
    struct timespec timeout;
    timeout.tv_sec = 1;
    timeout.tv_nsec = 0;

    //initialize msgvec
    memset(msgvec, 0, sizeof(msgvec));
    for (int i = 0; i < VLEN; i++) {
        iovecs[i].iov_base = bufs[i];
        iovecs[i].iov_len  = MAX_PACKET_SIZE;
        msgvec[i].msg_hdr.msg_iov    = &iovecs[i];
        msgvec[i].msg_hdr.msg_iovlen = 1;
    }

    //initialize ring buffer
    ring_buffer rb;
    rb.count = 0;
    rb.head = 0;
    rb.tail = 0;
    clock_gettime(CLOCK_MONOTONIC, &rb.last_p_time);
    memset(rb.requests, 0, sizeof(rb.requests));

    //initialize payload DHCP bufs, request DHCP fields
    unsigned char received_buf[VLEN][MAX_DHCP];
    dhcp_fields requests[MAX_RING_BUF_SIZE]; //syncronized with ring buffer
    struct timespec now; //for checking timeout
    double dif_time;

    //infinity receive cycle
    while(1)
    {
        int received = recvmmsg(sockfd, msgvec, VLEN, 0, &timeout);
        if (received > 0) {
            for (int i=0; i<received; i++)
            {
                int p_len = packet_parser(received_buf[i], bufs[i]);
                if (p_len <= 0) continue;
                printf("Packet received: %d\n", received);
                if (dhcp_receiver(received_buf[i], rb.requests[rb.tail], &requests[rb.tail]) < 0) continue;
                if (new_rb_record(&rb))
                {
                    rb_process(&rb, ctx, requests, sockfd, server);
                }
            }
            //checking ring buffer's timeout
            clock_gettime(CLOCK_MONOTONIC, &now);
            dif_time = now.tv_sec - rb.last_p_time.tv_sec;
            if ((rb.count >= RING_BUF_TRIGGER_COUNT) || dif_time >= RING_BUF_TIMEOUT)
            {
                rb_process(&rb, ctx, requests, sockfd, server);
            }

        } else if (received == 0) {
            printf("timeout\n");
            if (rb.count > 0) rb_process(&rb, ctx, requests, sockfd, server);
        } else {
            perror("recvmmsg\n");
            break;
        }
        }
    
    redisFree(ctx);
    close(sockfd);
    return 0;
}
