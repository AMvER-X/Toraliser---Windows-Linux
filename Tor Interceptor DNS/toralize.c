/* toralise.c*/

#include "toralize.h"

/*
This is a CLI argument you can add before webrequest to route traffic through the TOR network. This is done by routing traffic through predefined 
proxy servers on the Tor network. This is perfect, for when you want to add a layer of security to your web requests or to even boot an application 
and have it's network traffic roture through the Tor network.

Make sure TOR is installed and running on port 9050.


General use syntax:
./toralize (IP address) (port no.)
e.g. ./toralize 192.168.12.4 80
*/

// Handles request for the connect function over sock4, initialses struct
Req *Request(struct sockaddr_in *sock2)
{
    Req *req;

    req = malloc(reqsize);
    if (req == NULL)
    {
        perror("malloc");
        return NULL;
    }
    
    req->vn = 4;
    req->cd = 1;
    req->dstport = sock2->sin_port;

    #ifdef _WIN32
    req->dstip = sock2->sin_addr.s_un.s_addr;
    #else
    req->dstip = sock2->sin_addr.s_addr;
    #endif

    strncpy(req->userid, USERNAME, 8); 

    return req;
}

/*
Helper function for a DNS parse
Parses a DNS name from a packet and handles compression
Parameters:
'packet' = full DNS packet
'packet_len' = the packets length
'offset' = current offset into packet
'out' = a buffer to store the resulting domain name (dot-seperated)
'out_len' = size of said buffer

Func returns new offset after the name (if no pointer redirection)
or the offset of the original call if pointers were used

Returns -1 on error
*/ 
int parseDNSName(const unsigned char *packet, int packet_len, int offset, char *out, int out_len)
{
    int out_index = 0;
    int jump = 0;                 // Flag: jumped using pointer?
    int original_offset = offset; //For if we jump

    while(offset < packet_len)
    {
        unsigned char len = packet[offset];

        // End of name
        if (len == 0)
        {
            offset++;
            break;
        }

        // Check for pointer (compression)
        if ((len & 0xC0) == 0xC0)
        {
            if (offset + 1 >= packet_len)
            {
                return -1;
            }
            
            int pointer = ((len & 0x3F) << 8) | packet[offset + 1];
            if (pointer >= packet_len)
            {
                return -1;
            }
            // Save original offset if this is 1st jump
            if (!jump)
            {
                original_offset = offset + 2;
            }
            
            offset = pointer;
            jump = 1;
            continue;
        }
        else
        {
            //regular label
            offset++; // Move past length byte 
            if (offset + len > packet_len)
            {
                return -1;
            }
            
            if (out_index != 0)
            {
                if (out_index < out_len - 1)
                {
                    out[out_index] = '.';
                }
                else
                {
                    return -1;
                }
            }
            if (out_index + len >= out_len)
            {
                return -1;
            }
            memcpy(out + out_index, packet + offset, len);
            out_index += len;
            offset += len;
        } 
    }

    if (out_index >= out_len)
    {
        return -1;
    }
    out[out_index] = '\0';

    // If we jump, return the original offset
    return jump ? original_offset : offset;
}
/*
Resolves a hostname to an IP address using a DNS query over Tor

This function sends a DNS query for the given hostname and processes the response to extract the resolved IP address

'hostname' = string representing the domain name to be resolved
'resolved_addr' = pointer to a `struct sockaddr_in` where the resolved IP address will be stored

`resolved_addr->sin_family`: Set to `AF_INET` (IPv4).
`resolved_addr->sin_addr.s_addr`: Stores the resolved IPv4 address.
`resolved_addr->sin_port`: Usually set to 0, since this function only resolves DNS.
*/
int torDNSQuery(const char *hostname, struct sockaddr_in *resolved_addr)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        return -1;
    }

    //Creation of socket
    struct sockaddr_in torAddr;
    memset(&torAddr, 0, sizeof(torAddr));
    torAddr.sin_family = AF_INET;
    torAddr.sin_port = htons(TORDNSPROXYPORT);
    torAddr.sin_addr.s_addr = inet_addr(PROXY);

    // Building simple DNS query packet for an A record
    unsigned char query[512];
    memset(query, 0, sizeof(query));
    srand(time(NULL));

    unsigned short transactionID = rand() % 65536;
    // Transactrion ID
    query[0] = (transactionID >> 8) & 0xFF;
    query[1] = transactionID & 0xFF;

    /*
    ---------------------------------------------------------------------
    THESE WILL NEED TO BE UPDATED TO BE DYNAMICALLY CHANGED
    LEFT LIKE THIS FOR TESTING PURPOSES
    MAKE SURE TO UPDATE
    ---------------------------------------------------------------------
    */
    // Standard query flags
    query[2] = 0x01; 
    query[3] = 0x00;
    // QDCOUNT = 1
    query[4] = 0x00; 
    query[5] = 0x01;

    // Conversion of hostname to DNS query format
    int pos = 12;
    const char *hn = hostname;
    while(*hn)
    {
        const char *dot = strchr(hn, '.');
        int len = dot ? (dot - hn) : strlen(hn);
        query[pos++] = len;
        memcpy(&query[pos], hn, len);
        pos += len;
        if (dot)
            hn = dot + 1;
        else
            break;
    }
    // Terminate the QNAME
    query[pos++] = 0x00;

    // QTYPE = A (host address)
    query[pos++] = 0x00;
    query[pos++] = 0x01;

    // QCLASS = IN (internet)
    query[pos++] = 0x00;
    query[pos++] = 0x01;

    // Sending the DNS packet through the TOR network, on the TOR's DNS port
    if (sendto(sockfd, query, pos, 0, (struct sockaddr *)&torAddr, sizeof(torAddr)) < 0)
    {
        perror("sendto");
        close(sockfd);
        return -1;
    }

    // Receive the DNS response
    unsigned char response[512];
    socklen_t addrlen = sizeof(torAddr);

    int rec = recvfrom(sockfd, response, sizeof(response), 0, (struct sockaddr *)&torAddr, &addrlen);
    if (rec < 0)
    {
        perror("recvfrom");
        close(sockfd);
        return -1;
    }
    close(sockfd);

    if (rec < 12)
    {
        fprintf(stderr, "DNS response too short\n");
        return -1;
    }

    //This will be the code for the parser
    struct DNSHeader header;
    memcpy(&header, response, sizeof(header));
    header.id = ntohs(header.id);
    header.flags = ntohs(header.flags);
    header.qdcount = ntohs(header.qdcount);
    header.ancount = ntohs(header.ancount);
    header.nscount = ntohs(header.nscount);
    header.arcount = ntohs(header.arcount);

    // Don't need question section, skip over hence start at offset of 12
    int offset = 12;
    char name_buff[256];
    for (int i = 0; i < header.qdcount; i++)
    {
        int ret = parseDNSName(response, rec, offset, name_buff, sizeof(name_buff));
        if (ret < 0)
        {
            fprintf(stderr, "Failed to parse question name\n");
            return -1;
        }

        offset = ret;
        // Skip QTYPE and QCLASS (4 bytes)
        offset += 4;
        if (offset >= rec)
        {
            fprintf(stderr, "Unexpected end of packet in question section\n");
            return -1;
        }
    }

    // Loop through answer records to find an A record
    int found = 0;
    for (int i = 0; i < header.ancount; i++)
    {
        // Parse the answer name, even though it isn't necessarily used
        int ret = parseDNSName(response, rec, offset, name_buff, sizeof(name_buff));
        if (ret < 0)
        {
            fprintf(stderr, "Failed to parse question name\n");
            return -1;
        }
        offset = ret;
        if (offset + 10 > rec) // must have type, class, TTL and rdlength
        {
            fprintf(stderr, "DNS answer too short\n");
            return -1;
        }

        // Read TYPE, CLASS, TTL, RDLENGTH
        uint16_t type = (response[offset] << 8) | response[offset + 1];
        uint16_t class = (response[offset + 2] << 8) | response[offset + 3];
        // Skip TTL (4 bytes)
        uint16_t rdlength = (response[offset + 8] << 8) | response[offset + 9];
        offset += 10;

        if (offset + rdlength > rec)
        {
            fprintf(stderr, "DNS RDATA exceeds packet length\n");
            return -1;
        }

        // Look for A record (TYPE 1, CLASS 1)
        if (type == 1 && class == 1 && rdlength == 4)
        {
            // We have found an IPv4 address
            char ip_str[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &response[offset], ip_str, sizeof(ip_str)) == NULL)
            {
                perror("inet_ntop");
                return -1;
            }
            resolved_addr->sin_family = AF_INET;
            resolved_addr->sin_addr.s_addr = inet_addr(ip_str);
            resolved_addr->sin_port = 0;
            found = 1;
            break;
        }
        offset += rdlength;
    }

    if (!found)
    {
        fprintf(stderr, "No A record found for this DNS response\n");
        return -1;
    }

    return 0;
}

/* 
Our function hooked version of getaddrinfo
This is compiled as a shared library and preloaded (using LD_PRELOAD)

Allows all DNS requests to be executed through this program
Applications calling getaddrinfo() will use this version
*/

//Windows Version
#ifdef _WIN32
/*
Turns the socket connect function into a hooked shared lib, which we can use on any cli command.
We are using the arguments provided by the application, here it is socket 2 and s2.
We will have 2 versions one for Windos and one for Unix/ Linux.ABC
*/
int connect(int s2, const struct sockaddr *sock2, int addrlen)
{
    WSADATA wsaDATA;
    if (WSAStartup(MAKEWORD(2, 2), &wsaDATA) != 0)
    {
        perror("WSAStartup");
        return -1;
    }

    int s;
    struct sockaddr_in sock;
    Req *req;
    Res *res;
    char buf[ressize];
    int success; //acts as our predicate

    //Creation of function pointer for connect function, based on Windows or Unix OS
    int (*p)(int, const struct sockaddr*, int);

    //find next occurance of connect function
    p = (int (*)(int, const struct sockaddr*, int))GetProcAddress(GetModuleHandle("Ws2_32.dll"), "connect"); 
    if (!p)
    {
        perror("GetProcAddress");
        WSACleanup();
        return -1;
    }

    //Create socket
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
    {
        perror("socket");
        WSACleanup();
        return -1;
    }

    // Perparing structure of socket
    sock.sin_family = AF_INET;
    sock.sin_port = htons(TORDNSPROXYPORT);
    sock.sin_addr.s_addr = inet_addr(PROXY);

    //Connection of socket
    if (p(s, (struct sockaddr *)&sock, sizeof(sock)))
    {
        perror("connect");
        WSACleanup();
        return -1;
    }
    
    //sending request
    printf("Connected to proxy\n");
    req = Request((struct sockaddr_in *)sock2);
    if (req == NULL)
    {
        close(s);
        WSACleanup();
        return -1;
    }

    if (write(s, req, reqsize) != reqsize)
    {
        perror("write");
        close(s);
        WSACleanup();
        free(req);
        return -1;
    }

    memset(buf, 0, ressize); //cleans the buffer with 0's
    if (read(s, buf, ressize) < 1)
    {
        perror("read");
        free(req);
        close(s);

        return -1;
    } 

    //recieving response
    res = (Res *)buf;
    success = (res->cd == 90); //if cd is 90 success if true (1) else false (0)
    if (!success)
    {
        fprintf(stderr, "Unable to traverse" 
            "the proxy, error code: %d\n",
        res->cd);

        close(s);
        free(req);

        return -1;
    }

    printf("Successfully connected through the proxy to "
            "%s:%d\n");

    dup2(s, s2);
    free(req);

    WSACleanup();
    return 0;
}

/* 
Our function hooked version of getaddrinfo for the windows OS
This is compiled as a shared library and preloaded (using LD_PRELOAD)

Allows all DNS requests to be executed through this program
Applications calling getaddrinfo() will use this version
*/
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
    WSADATA wsaDATA;
    if (WSAStartup(MAKEWORD(2, 2), &wsaDATA) != 0)
    {
        perror("WSAStartup");
        return -1;
    }

    // Check if node is an IP address already
    struct in_addr addr;
    if (inet_aton(node, &addr))
    {
        // Get next instance of the getaddrinfo() function
        // This is a different (easier to read) way of performing the function hook for getaddrinfo() func
        typedef int (*orig_getaddrinfo_f_type)(const char *, const char *, const struct addrinfo *, struct addrinfo **);

        //It's an IP already, call original getaddrinfo
        orig_getaddrinfo_f_type orig_getaddrinfo;
        orig_getaddrinfo = (orig_getaddrinfo_f_type)GetProcAddress(GetModuleHandle("Ws2_32.dll"), "getaddrinfo");

        if (!orig_getaddrinfo)
        {
            fprintf(stderr, "Error in dlsym(getaddrinfo)\n");
            return -1;
        }
        return orig_getaddrinfo(node, service, hints, res);
    }

    // If hostname, use cust DNS solution
    struct sockaddr_in resolved;
    if (torDNSQuery(node, resolved) != 0)
    {
        fprintf(stderr, "torDNSQuery failed for %s\n", node);
        return -1;
    }

    // Building a minimal addrinfo structure
    struct addrinfo *ai = calloc(1, sizeof(struct addrinfo));
    if (!ai)
    {
        perror("calloc");
        return -1;
    }

    ai->ai_family = AF_INET;
    ai->ai_socktype = (hints && hints->ai_socktype) ? hints->ai_socktype : SOCK_STREAM;
    ai->ai_protocol = (hints && hints->ai_protocol) ? hints->ai_protocol : SOCK_STREAM;
    
    struct sockaddr_in *sa = malloc(sizeof(struct sockaddr_in));
    if (!sa)
    {
        free(sa);
        perror("malloc");
        return -1;
    } 

    memcpy(sa, &resolved, sizeof(struct sockaddr_in));

    // if a service (port) is available, we need to then convert it
    if (service)
    {
        int port = atoi(service);
        sa->sin_port = htons(port);
    }

    ai->ai_addr = (struct sockaddr *)sa;
    ai->ai_addrlen = sizeof(struct sockadr_in);
    ai->ai_next = NULL;

    *res = ai;
    WSACleanup();
    return 0;
}
#elif defined(__unix__) || defined(__linux__)
//Unix/ Linux version
int connect(int s2, const struct sockaddr *sock2, socklen_t addrlen)
{
    int s;
    struct sockaddr_in sock;
    Req *req;
    Res *res;
    char buf[ressize];
    int success; //acts as our predicate

    //Creation of function pointer for connect function, based on Windows or Unix OS
    int (*p)(int, const struct sockaddr*, socklen_t); 

    //find next occurance of connect function
    p = (int (*)(int, const struct sockaddr*, socklen_t))dlsym(RTLD_NEXT, "connect"); 
    if (!p)
    {
        perror("dlsym");
        return -1;
    }
    //Create socket
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
    {
        perror("socket");
        return -1;
    }

    // Perparing structure of socket
    sock.sin_family = AF_INET;
    sock.sin_port = htons(PROXYPORT);
    sock.sin_addr.s_addr = inet_addr(PROXY);

    //Connection of socket
    if (p(s, (struct sockaddr *)&sock, sizeof(sock)))
    {
        perror("connect");
        return -1;
    }
    
    //sending request
    printf("Connected to proxy\n");
    req = Request((struct sockaddr_in *)sock2);
    if (req == NULL)
    {
        close(s);
        return -1;
    }
    
    //Sending of data
    if (write(s, req, reqsize) != reqsize)
    {
        perror("write");
        free(req);
        close(s);
        return -1;
    }

    memset(buf, 0, ressize); //cleans the buffer with 0's
    if (read(s, buf, ressize) < 1)
    {
        perror("read");
        free(req);
        close(s);

        return -1;
    } 

    //recieving response
    res = (Res *)buf;
    success = (res->cd == 90); //if cd is 90 success if true (1) else false (0)
    if (!success)
    {
        fprintf(stderr, "Unable to traverse" 
            "the proxy, error code: %d\n",
        res->cd);

        close(s);
        free(req);

        return -1;
    }

    printf("Successfully connected through the proxy to "
            "%s:%d\n", host, port);

    //
    dup2(s, s2);
    free(req);

    return 0;
}

/* 
Our function hooked version of getaddrinfo for Unix/ Linux based OS
This is compiled as a shared library and preloaded (using LD_PRELOAD)

Allows all DNS requests to be executed through this program
Applications calling getaddrinfo() will use this version
*/
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
    // Check if node is an IP address already
    struct in_addr addr;
    if (inet_aton(node, &addr))
    {
        // Pointer for the original getaddrinfo func
        // This is a different (easier to read) way of performing the function hook for getaddrinfo() func
        typedef int (*orig_getaddrinfo_f_type)(const char *, const char *, const struct addrinfo *, struct addrinfo **);

        //It's an IP already, call original getaddrinfo
        orig_getaddrinfo_f_type orig_getaddrinfo;
        orig_getaddrinfo = (orig_getaddrinfo_f_type)dlsym(RTLD_NEXT, "getaddrinfo");

        if (!orig_getaddrinfo)
        {
            fprintf(stderr, "Error in dlsym(getaddrinfo)\n");
            return -1;
        }
        return orig_getaddrinfo(node, service, hints, res);
    }

    // If hostname, use cust DNS solution
    struct sockaddr_in resolved;
    if (torDNSQuery(node, resolved) != 0)
    {
        fprintf(stderr, "torDNSQuery failed for %s\n", node);
        return -1;
    }

    // Building a minimal addrinfo structure
    struct addrinfo *ai = calloc(1, sizeof(struct addrinfo));
    if (!ai)
    {
        perror("calloc");
        return -1;
    }

    ai->ai_family = AF_INET;
    ai->ai_socktype = (hints && hints->ai_socktype) ? hints->ai_socktype : SOCK_STREAM;
    ai->ai_protocol = (hints && hints->ai_protocol) ? hints->ai_protocol : SOCK_STREAM;
    
    struct sockaddr_in *sa = malloc(sizeof(struct sockaddr_in));
    if (!sa)
    {
        free(sa);
        perror("malloc");
        return -1;
    } 

    memcpy(sa, &resolved, sizeof(struct sockaddr_in));

    // if a service (port) is available, we need to then convert it
    if (service)
    {
        int port = atoi(service);
        sa->sin_port = htons(port);
    }

    ai->ai_addr = (struct sockaddr *)sa;
    ai->ai_addrlen = sizeof(struct sockadr_in);
    ai->ai_next = NULL;

    *res = ai;
    return 0;
}

#endif