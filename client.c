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
#include "ssl.h"
#include <assert.h>
#include <openssl/ssl.h>

#define BUFSIZE (10 * 1024 * 1024)

char* get_server_response(int client_fd, char *req) {
    int sockfd, n, optval; // sockfd = server_fd
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
      // TODO: possible change pthread_cancel in handle_error to pthread_exit?
      close(client_fd);
      pthread_exit(NULL); // If we use handle_error, then pthread_cancel segfaults
    }
    portno = arr[2];
    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
	  (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(*portno);

    /* connect: create a connection with the server */
    if (connect(sockfd, &serveraddr, sizeof(serveraddr)) < 0) {
      close(sockfd);
      handle_error(client_fd, pthread_self());
    }
    /* send the message line to the server */
    u_int32_t i = (strstr(req, "\r\n\r\n") + 4) - req;
    n = write(sockfd, req, i);
    if (n < 0) {
      close(sockfd);
      handle_error(client_fd, pthread_self());
    }

    u_int32_t content_length = BUFSIZE + 1;
    /* print the server's reply */
    bzero(buf, BUFSIZE);
    i = 0;
    
    n = read(sockfd, buf, 1024);

    if (n < 0) {
      close(sockfd);
      // handle_error(client_fd, pthread_self());
    }

    i += n;
    while (n > 0 && i < content_length) {
      if (content_length > BUFSIZE && check_header(buf, "Content-Length: ") != NULL) {
        content_length = parse_int_from_header(buf, "Content-Length: ");
        content_length = content_length + (strstr(buf, "\r\n\r\n") + 4 - buf);
      }

      n = read(sockfd, buf + i, 1024);

      if (n < 0) {
        close(sockfd);
        // handle_error(client_fd, pthread_self());
      }

      i += n;
    }
    close(sockfd);
    free(arr[0]);
    free(arr[1]);
    free(arr[2]);
    free(arr);
    return buf;
}


char* ssl_get_server_response(SSL *ssl_client, SSL *ssl_server, int client_fd, char *req) 
{
    int sockfd, n, optval; // sockfd = server_fd
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
    printf("(%d) ssl_get_server_response: hostname %s\n", client_fd, hostname);

    server = gethostbyname(hostname);
    if (server == NULL) {
      // TODO: possible change pthread_cancel in handle_error to pthread_exit?
      close(client_fd);
      pthread_exit(NULL); // If we use handle_error, then pthread_cancel segfaults
    }
    portno = arr[2];
    if (*portno = 80) {
      // TODO: move to parse.c
      *portno = 443;
    }
    printf("(%d) ssl_get_server_response: portno %d\n", client_fd, *portno);
    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
	  (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(*portno);

    /* send the message line to the server */
    u_int32_t i = (strstr(req, "\r\n\r\n") + 4) - req;
    n = SSL_write(ssl_server, req, i);
    if (n < 0) {
      printf("ssl_get_server_response: ERROR writing to server\n");
      printf("ssl_get_server_response: SSL_write returned %d\n", n);
      ssl_print_error(ssl_server, n);
      close(sockfd);
      handle_error(client_fd, pthread_self());
    }
    printf("*=======================================\n");
    printf("ssl_get_server_response\nwrote %d bytes to server:\n%s\n", n, req);
    printf("=======================================*\n\n");

    u_int32_t content_length = BUFSIZE - 1;

    bzero(buf, BUFSIZE);
    i = 0;
    printf("(%d) ssl_get_server_response: About to SSL_read from server\n", client_fd);
    n = SSL_read(ssl_server, buf, 1024);
      printf("(%d) ssl_get_server_response: read %d bytes\n", client_fd, n);

    if (n <= 0) {
      close(sockfd);
      handle_error(client_fd, pthread_self());
    }

    i += n;
    while (SSL_pending(ssl_server) > 0 && i < content_length) {
      if (content_length > BUFSIZE && check_header(buf, "Content-Length: ") != NULL) {
        content_length = parse_int_from_header(buf, "Content-Length: ");
        content_length = content_length + (strstr(buf, "\r\n\r\n") + 4 - buf);
      }
      printf("(%d) ssl_get_server_response: About to SSL_read from server\n", client_fd);
      n = SSL_read(ssl_server, buf + i, 1024);
      printf("(%d) ssl_get_server_response: read %d bytes\n", client_fd, n);

      if (n < 0) {
        close(sockfd);
        handle_error(client_fd, pthread_self());
      }

      i += n;
      if (n == 0)
        break;
    }

    printf("*=======================================\n");
    printf("ssl_get_server_response\nread %d bytes from server:\n%s\n", i, buf);
    printf("=======================================*\n\n");


    ssl_close(sockfd, ssl_server, NULL);
    close(sockfd);
    free(arr[0]);
    free(arr[1]);
    free(arr[2]);
    free(arr);
    return buf;
}
