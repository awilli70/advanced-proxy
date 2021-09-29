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

char* get_server_response(char *req) {
    int sockfd, n;
    int *portno;
    u_int32_t res_sz = 0;
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
    u_int32_t i = (strstr(req, "\r\n\r\n") + 4) - req;
    n = write(sockfd, req, i);
    if (n < 0) 
      error("ERROR writing to socket");

    u_int32_t content_length = BUFSIZE + 1;
    /* print the server's reply */
    bzero(buf, BUFSIZE);
    i = 0;
    n = read(sockfd, buf, BUFSIZE);
    if (n < 0) 
        error("ERROR reading from socket");
    i += n;
    while (n > 0 && i < content_length) {
      if (content_length > BUFSIZE && strstr(buf, "Content-Length: ") != NULL) {
        content_length = 0;
        char *cont_idx = strstr(buf, "Content-Length: ") + 16;
        while (*cont_idx != ' ' && *cont_idx != '\r') {
            if (content_length > 0) {
                content_length = content_length * 10;    
            }
            content_length = content_length + (*cont_idx - '0');
            cont_idx = cont_idx + 1;
        }
        content_length = content_length + (strstr(buf, "\r\n\r\n") + 4 - buf);
      }
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