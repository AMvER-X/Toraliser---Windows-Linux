/* toralize.h */
#ifndef TORALIZE_H
#define TORALIZE_H

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>

#include <dlfcn.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <string.h>

// Error codes
enum error_codes
{
    CONNECT_HOOK = -99,
    SOCKET_CREATION,
    SOCKET_CONNECT,
    SOCKET_ERROR,
    MALLOC,
    REQUEST,
    WRITE,
    READ,
    RECIEVE_RESPONSE,
    SEND_TO,
    RECVFROM,
    DNSRESPSIZE,
    POINTER_COMPRESSION_LENGTH,
    POINTER_SIZE,
    DNS_NAME_SIZE,
    OUT_INDEX_LEN,
    DNS_DLSYM,
    PARSE_DNS_NAME,
    DNS_ANSWER_LEN,
    DNS_DATA_LEN,
    IPV4_STRING,
    IP_FOUND,
    TOR_DNS_QUERY,
    CALLOC_FUNC,
    MALLOC_FUNC
};

#define PROXY "127.0.0.1"
#define TORDNSPROXYPORT 9053
#define TORPROXYPORT 9050
#define USERNAME "toralize" //Need an 8 char string username for rounding, used 7 chars in name and then null at end for termination.
#define reqsize sizeof(struct proxy_request)
#define ressize sizeof(struct proxy_response)

/*
Structure of structs
            +----+----+----+----+----+----+----+----+----+----+....+----+
            | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
            +----+----+----+----+----+----+----+----+----+----+....+----+
# of bytes:	   1    1      2              4           variable       1
*/

struct proxy_request
{
    uint8_t vn;
    uint8_t cd;
    uint16_t dstport;
    uint32_t dstip;
    unsigned char userid[8]; // We now would like a 7 length userid so that the struct can end in a null (0)
};

typedef struct proxy_request Req;

/*
Structure of structs
                +----+----+----+----+----+----+----+----+
                | VN | CD | DSTPORT |      DSTIP        |
                +----+----+----+----+----+----+----+----+
 # of bytes:	   1    1      2              4

 dstport and dstip are ignored but we define them for struct size
*/

struct proxy_response
{
    uint8_t vn;
    uint8_t cd;
    uint16_t dstport;
    uint32_t dstip;
};

typedef struct proxy_response Res;

// struct for DNS header, 12 bytes
struct DNSHeader
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};


// Function declerations
Req *Request(struct sockaddr_in *);
int connect(int, const struct sockaddr *, socklen_t);
int TorDNSQuery(const char *, struct sockaddr_in *);
int ParseDNSName(const unsigned char *, int, int, char *, int);
int getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);



#endif // TORALIZE_H