/* toralize.h*/
#ifndef TORALIZE_H
#define TORALIZE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <dlfcn.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#endif

#define PROXY "127.0.0.1"
#define TORDNSPROXYPORT 9053
#define USERNAME "toraliz" //Need an 8 char string username for rounding, used 7 chars in name and then null at end for termination.
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
    unsigned char userid[8];  // We now would like a 7 length userid so that the struct can end in a null (0)
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


Req *Request(struct sockaddr_in*);

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

// Adjusts the 'connect' function to make it compatible for windows and/ or Unix/ Linux.
#ifdef _WIN32
int connect(int, const struct sockaddr *, int);
int getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);
#elif defined(__unix__) || defined(__linux__)
int connect(int, const struct sockaddr *, socklen_t);
int torDNSQuery(const char *, struct sockaddr_in *);
int parseDNSName(const unsigned char *, int, int, char *, int);
int getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);
#endif

#endif // TORALIZE_H