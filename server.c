/*
 * echoserver.c - A simple connection-based echo server
 * usage: echoserver <port>
 */

#include "client.h"
#include "error.h"
#include "parse.h"
#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

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

void *memmem(const void *haystack, size_t hlen, const void *needle,
             size_t nlen) {
  int needle_first;
  const void *p = haystack;
  size_t plen = hlen;

  if (!nlen)
    return NULL;

  needle_first = *(unsigned char *)needle;

  while (plen >= nlen && (p = memchr(p, needle_first, plen - nlen + 1))) {
    if (!memcmp(p, needle, nlen))
      return (void *)p;

    p++;
    plen = hlen - (p - haystack);
  }

  return NULL;
}

int get_client_connfd(int listenfd) {
  int connfd;                    /* connection socket */
  struct sockaddr_in clientaddr; /* client addr */
  struct hostent *hostp;         /* client host info */
  char *hostaddrp;               /* dotted decimal host addr string */
  int clientlen = sizeof(clientaddr);
  connfd = accept(listenfd, (struct sockaddr *)&clientaddr, &clientlen);
  if (connfd < 0)
    return -1; // Error handling: Don't want to kill this main thread or close
               // listenfd

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
char *read_client_req(int client_fd) {
  char *buf = malloc(sizeof(char) * REQBUFSIZE); /* message buffer */
  int n = 0;
  assert(buf != NULL);
  bzero(buf, REQBUFSIZE);
  uint32_t i = 0;
  n = read(client_fd, buf, 1024);
  if (n < 0) {
    handle_error(client_fd);
  }
  i += n;
  while (memmem(buf, i, "\r\n\r\n", 4) == NULL) {
    n = read(client_fd, buf + i, 1024);

    if (n < 0) {
      handle_error(client_fd);
      break;
    }

    i += n;
  }
  return buf;
}

/* read: read input string from the client */
char *ssl_read_client_req(SSL *ssl_client, int client_fd) {
  char *buf = malloc(sizeof(char) * REQBUFSIZE); /* message buffer */
  int n = 0;
  assert(buf != NULL);
  bzero(buf, REQBUFSIZE);
  uint32_t i = 0;

  n = SSL_read(ssl_client, buf, 1024);
  if (n <= 0) {
    printf("(%03d) ssl_read_client_req error from SSL_read\n", client_fd);
    ssl_print_error(ssl_client, n);
    handle_error(client_fd);
  }

  i += n;

  while (memmem(buf, i, "\r\n\r\n", 4) == NULL) {
    n = SSL_read(ssl_client, buf + i, 1024);
    if (n <= 0) {
      printf("(%03d) ssl_read_client_req error from SSL_read\n", client_fd);
      ssl_print_error(ssl_client, n);
      handle_error(client_fd);
    }

    i += n;
  }

  return buf;
}

void write_client_response(int client_fd, char *buf) {
  uint32_t i = 0;
  int n = 0;
  uint32_t header_length = (strstr(buf, "\r\n\r\n") + 4) - buf;
  i = parse_int_from_header(buf, "Content-Length: ");
  if (i != (10 * REQBUFSIZE)) {
    n = write(client_fd, buf, sizeof(char) * (i + header_length));
    // assert(n == sizeof(char) * (i + header_length));
  } else {
    n = write(client_fd, buf, sizeof(char) * i);
  }

  if (n < 0) {
    handle_error(client_fd);
    return;
  }

  return;
}

void ssl_write_client_response(SSL *ssl_client, int client_fd, char *buf) {
  uint32_t i = 0;
  int n = 0;
  uint32_t header_length = (strstr(buf, "\r\n\r\n") + 4) - buf;
  if (strstr(buf, "Content-Length: ") != NULL) {
    i = parse_int_from_header(buf, "Content-Length: ");
  } else if (strstr(buf, "Transfer-Encoding") != NULL && strstr(buf, "chunked" != NULL)) {
    i = (strstr(buf, "\r\n0\r\n\r\n") + 7) - buf - header_length;
  } else {
    handle_error(client_fd);
  }
  
  if (i != (10 * REQBUFSIZE)) {
    n = SSL_write(ssl_client, buf, sizeof(char) * (i + header_length));
  } else {
    n = SSL_write(ssl_client, buf, sizeof(char) * i);
  }

  if (n < 0) {
    printf("(%03d) ERROR SSL_write (n = %d)\n", n);
    ssl_print_error(ssl_client, n);
    handle_error(client_fd);
  }

  return;
}