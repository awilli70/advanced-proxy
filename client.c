/*
 * client.c - A simple TCP client for use in HTTP proxy
 */
#include "error.h"
#include "parse.h"
#include "ssl.h"
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

#define BUFSIZE (10 * 1024 * 1024)

char *get_server_response(int client_fd, char *req) {
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
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
             sizeof(int));

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
  bzero((char *)&serveraddr, sizeof(serveraddr));
  serveraddr.sin_family = AF_INET;
  bcopy((char *)server->h_addr, (char *)&serveraddr.sin_addr.s_addr,
        server->h_length);
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

  // n = read(sockfd, buf, 1024);

  // if (n < 0) {
  //   close(sockfd);
  //   // handle_error(client_fd, pthread_self());
  // }

  // i += n;
  bool is_chunked = false;
  bool has_content_length = false;
  do {
    if (!is_chunked && !has_content_length) {
      if (content_length > BUFSIZE) {
        if (check_header(buf, "Content-Length: ") != NULL) {
          printf("(%03d) \"Content-Length\" found in header\n", client_fd);
          content_length = parse_int_from_header(buf, "Content-Length: ");
          content_length = content_length + (strstr(buf, "\r\n\r\n") + 4 - buf);
          has_content_length = true;
          if (i == content_length) {
            break;
          }
        } else if (check_header(buf, "Transfer-Encoding: chunked") != NULL) {
          printf("(%03d) Response is chunked\n");
          is_chunked = true;
        }
      }
    }

    n = read(sockfd, buf + i, 1024);

    if (n < 0) {
      close(sockfd);
      // handle_error(client_fd, pthread_self());
    }

    i += n;
    
    // If response is chunk encoded, return once we see the final chunk
    if (is_chunked && strstr(buf, "\r\n0\r\n\r\n") != NULL) {
      break;
    }
  } while (n > 0 && i < content_length);

  // while (n > 0 && i < content_length) {
  //   if (!is_chunked) {
  //     if (content_length > BUFSIZE) {
  //       if (check_header(buf, "Content-Length: ") != NULL) {
  //         content_length = parse_int_from_header(buf, "Content-Length: ");
  //         content_length = content_length + (strstr(buf, "\r\n\r\n") + 4 - buf);
  //         if (i == content_length) {
  //           break;
  //         }
  //       } else if (check_header(buf, "Transfer-Encoding: chunked") != NULL) {
  //         printf("(%03d) Response is chunked\n");
  //         is_chunked = true;
  //       }
  //     }
  //   }

  //   n = read(sockfd, buf + i, 1024);

  //   if (n < 0) {
  //     close(sockfd);
  //     // handle_error(client_fd, pthread_self());
  //   }

  //   i += n;
    
  //   // If response is chunk encoded, return once we see the final chunk
  //   if (is_chunked && strstr(buf, "\r\n0\r\n\r\n") != NULL) {
  //     break;
  //   }
  // }
  close(sockfd);
  free(arr[0]);
  free(arr[1]);
  free(arr[2]);
  free(arr);
  return buf;
}

char *ssl_get_server_response(SSL *ssl_client, SSL *ssl_server, int client_fd,
                              char *req) {
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
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
             sizeof(int));

  /* gethostbyname: get the server's DNS entry */
  hostname = arr[1];
  printf("(%03d) ssl_get_server_response: hostname %s\n", client_fd, hostname);

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
  printf("(%03d) ssl_get_server_response: portno %d\n", client_fd, *portno);
  /* build the server's Internet address */
  bzero((char *)&serveraddr, sizeof(serveraddr));
  serveraddr.sin_family = AF_INET;
  bcopy((char *)server->h_addr, (char *)&serveraddr.sin_addr.s_addr,
        server->h_length);
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

  printf("(%03d) wrote %d bytes to server\n", client_fd, n);

  u_int32_t content_length = BUFSIZE + 1;

  bzero(buf, BUFSIZE);
  i = 0;

  n = SSL_read(ssl_server, buf, 1024);

  if (n <= 0) {
    close(sockfd);
    handle_error(client_fd, pthread_self());
  }

  i += n;
  bool is_chunked = false;
  while (n > 0 && i < content_length) {
    if (!is_chunked) {
      if (content_length > BUFSIZE) {
        if (check_header(buf, "Content-Length: ") != NULL) {
          content_length = parse_int_from_header(buf, "Content-Length: ");
          content_length = content_length + (strstr(buf, "\r\n\r\n") + 4 - buf);
        } else if (check_header(buf, "Transfer-Encoding: chunked") != NULL) {
          printf("(%03d) Response is chunked\n", client_fd);
          is_chunked = true;
        }
      }
    }

    n = SSL_read(ssl_server, buf + i, 1024);

    if (n < 0) {
      close(sockfd);
      handle_error(client_fd, pthread_self());
    }

    i += n;
    
    // If response is chunk encoded, return once we see the final chunk
    if (is_chunked && (strstr(buf, "\r\n0\r\n\r\n") != NULL)) {
      printf("(%03d) Final chunk detected, done reading\n", client_fd);
      break;
    }
  }

  printf("(%03d) read %d bytes from server\n", client_fd, i);

  ssl_close(sockfd, ssl_server, NULL);
  close(sockfd);
  free(arr[0]);
  free(arr[1]);
  free(arr[2]);
  free(arr);
  return buf;
}
