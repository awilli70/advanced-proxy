/* 
 * echoserver.c - A simple connection-based echo server 
 * usage: echoserver <port>
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include "client.h"
#include "parse.h"

#define REQBUFSIZE 4096

#if 0
/* 
 * Structs exported from netinet/in.h (for easy reference)
 */

/* Internet address */
struct in_addr {
  unsigned int s_addr; 
};

/* Internet style socket address */
struct sockaddr_in  {
  unsigned short int sin_family; /* Address family */
  unsigned short int sin_port;   /* Port number */
  struct in_addr sin_addr;	 /* IP address */
  unsigned char sin_zero[...];   /* Pad to size of 'struct sockaddr' */
};

/*
 * Struct exported from netdb.h
 */

/* Domain name service (DNS) host entry */
struct hostent {
  char    *h_name;        /* official name of host */
  char    **h_aliases;    /* alias list */
  int     h_addrtype;     /* host address type */
  int     h_length;       /* length of address */
  char    **h_addr_list;  /* list of addresses */
}
#endif

int get_client_connfd(int listenfd) {
    int connfd; /* connection socket */
    struct sockaddr_in clientaddr; /* client addr */
    struct hostent *hostp; /* client host info */
    char *hostaddrp; /* dotted decimal host addr string */
    int clientlen = sizeof(clientaddr);

    connfd = accept(listenfd, (struct sockaddr *) &clientaddr, &clientlen);
    if (connfd < 0) 
        error("ERROR on accept");

    /* gethostbyaddr: determine who sent the message */
    hostp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr, 
            sizeof(clientaddr.sin_addr.s_addr), AF_INET);
    if (hostp == NULL)
    error("ERROR on gethostbyaddr");
    hostaddrp = inet_ntoa(clientaddr.sin_addr);
    if (hostaddrp == NULL)
    error("ERROR on inet_ntoa\n");
    return connfd;
}
    
    

    /* read: read input string from the client */
char *read_client_req(int connfd) {
    char *buf = malloc(sizeof(char) * REQBUFSIZE); /* message buffer */
    int n = 0;
    assert(buf != NULL);
    bzero(buf, REQBUFSIZE);
    u_int32_t i = 0;
    n = read(connfd, buf, 1024);
    if (n < 0) 
        error("ERROR reading from socket");
    i += n;
    while (strstr(buf, "\r\n\r\n") == NULL) {
      n = read(connfd, buf + i, 1024);
      i += n;
    }
    return buf;
}
    
void write_client_response(int connfd, char* buf) {
    u_int32_t i = 0;
    int n = 0;
    u_int32_t header_length = (strstr(buf, "\r\n\r\n") + 4) - buf;
    i = parse_int_from_header(buf, "Content-Length: ");
    if (i != (10 * REQBUFSIZE)) {
      n = write(connfd, buf, sizeof(char) * (i + header_length));
      assert(n == sizeof(char) * (i + header_length));
    } else {
      n = write(connfd, buf, sizeof(char) * i);
    }
    if (n < 0) 
      error("ERROR writing to socket");
    return;
}