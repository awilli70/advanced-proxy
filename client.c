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
#include "error.h"
#include <assert.h>

#define BUFSIZE (10 * 1024 * 1024)


char* get_server_response(char *req) {
    int sockfd, n, optval;
    int *portno;
    u_int32_t res_sz = 0;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname;
    char *buf = malloc(sizeof(char) * BUFSIZE);
    assert(buf != NULL);

    void **arr = split_request(req);

    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

    optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, 
	            (const void *)&optval , sizeof(int));

    /* gethostbyname: get the server's DNS entry */
    hostname = arr[1];
    server = gethostbyname(hostname);
    if (server == NULL) {
        invalid_hostname(hostname);
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
    printf("Connected\n");
    /* send the message line to the server */
    u_int32_t i = (strstr(req, "\r\n\r\n") + 4) - req;
    n = write(sockfd, req, i);
    if (n < 0) 
      error("ERROR writing to socket");

    u_int32_t content_length = BUFSIZE + 1;
    /* print the server's reply */
    bzero(buf, BUFSIZE);
    i = 0;
    n = read(sockfd, buf, 1024);
    if (n < 0) 
        error("ERROR reading from socket");
    i += n;
    while (n > 0 && i < content_length) {
      if (content_length > BUFSIZE && check_header(buf, "Content-Length: ") != NULL) {
        content_length = parse_int_from_header(buf, "Content-Length: ");
        content_length = content_length + (strstr(buf, "\r\n\r\n") + 4 - buf);
      }
      n = read(sockfd, buf + i, 1024);
      i += n;
    }
    close(sockfd);
    free(arr[0]);
    free(arr[1]);
    free(arr[2]);
    free(arr);
    return buf;
}
