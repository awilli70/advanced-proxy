/* 
 * client.c - A simple TCP client for use in HTTP proxy
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include "parse.h"

#define BUFSIZE (10 * 1024 * 1024)

/* 
 * error - wrapper for perror
 */
void error(char *msg) {
    perror(msg);
    exit(0);
}

char* get_buf(char *req) {
    int sockfd, n;
    int *portno;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname;
    char *buf = malloc(sizeof(char) * BUFSIZE);
    if (buf == NULL) {
      error("Error allocating buffer");
    }
    void **arr = split_request(req);

    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

    /* gethostbyname: get the server's DNS entry */
    hostname = arr[1];
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s.\n", hostname);
        exit(0);
    }
    portno = arr[2];
    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
	  (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(*portno);

    /* connect: create a connection with the server */
    if (connect(sockfd, &serveraddr, sizeof(serveraddr)) < 0) 
      error("ERROR connecting");

    /* send the message line to the server */
    u_int32_t i = 0;
    n = write(sockfd, req, strlen(req));
    i += n;
    while (n > 0) {
      n = write(sockfd, req + i, strlen(req) - i);
      i += n;
    }
    if (n < 0) 
      error("ERROR writing to socket");


    /* print the server's reply */
    bzero(buf, BUFSIZE);
    i = 0;
    n = read(sockfd, buf, BUFSIZE);
    if (n < 0) 
        error("ERROR reading from socket");
    i += n;
    while (n > 0) {
      n = read(sockfd, buf + i, BUFSIZE);
      i += n;
    }
    close(sockfd);
    free(arr[0]);
    free(arr[1]);
    free(arr[2]);
    free(arr);
    return buf;
}