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
  int server_fd, n, optval; // server_fd = server_fd
  int *portno;
  u_int32_t res_sz = 0;
  struct sockaddr_in serveraddr;
  struct hostent *server;
  char *hostname;
  char *buf = malloc(sizeof(char) * BUFSIZE);
  assert(buf != NULL);

  void **arr = split_request(req, false);

  /* socket: create the socket */
  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    printf("(%03d) ERROR opening socket for server\n", client_fd);
    free(arr);
    handle_error(client_fd);
  }

  optval = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
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
  if (connect(server_fd, &serveraddr, sizeof(serveraddr)) < 0) {
    close(server_fd);
    handle_error(client_fd);
  }
  /* send the message line to the server */
  u_int32_t i = (strstr(req, "\r\n\r\n") + 4) - req;
  n = write(server_fd, req, i);
  if (n < 0) {
    close(server_fd);
    handle_error(client_fd);
  }

  u_int32_t content_length = BUFSIZE + 1;
  /* print the server's reply */
  bzero(buf, BUFSIZE);
  i = 0;

  bool is_chunked = false;
  bool has_content_length = false;
  do {
    if (!is_chunked && !has_content_length) {
      if (content_length > BUFSIZE) {
        if (check_header(buf, "Content-Length: ") != NULL) {
          content_length = parse_int_from_header(buf, "Content-Length: ");
          content_length = content_length + (strstr(buf, "\r\n\r\n") + 4 - buf);
          has_content_length = true;
          if (i == content_length) {
            break;
          }
        } else if (check_header(buf, "Transfer-Encoding: chunked") != NULL) {
          is_chunked = true;
        }
      }
    }

    n = read(server_fd, buf + i, 1024);

    if (n < 0) {
      close(server_fd);
    }

    i += n;
    
    // If response is chunk encoded, return once we see the final chunk
    if (is_chunked && strstr(buf, "\r\n0\r\n\r\n") != NULL) {
      break;
    }
  } while (n > 0 && i < content_length);

  close(server_fd);
  free(arr[0]);
  free(arr[1]);
  free(arr[2]);
  free(arr);
  return buf;
}

char *ssl_get_server_response(SSL *ssl_client, SSL *ssl_server, int client_fd,
                              char *req) {
  int server_fd, n, optval; // server_fd = server_fd
  int *portno;
  u_int32_t res_sz = 0;
  struct sockaddr_in serveraddr;
  struct hostent *server;
  char *hostname;
  char *buf = malloc(sizeof(char) * BUFSIZE);
  assert(buf != NULL);

  void **arr = split_request(req, true);

  /* socket: create the socket */
  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    printf("(%03d) ERROR opening socket for server\n", client_fd);
    free(arr);
    ssl_close(client_fd, ssl_client, NULL);
    handle_error(client_fd);
  }

  optval = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
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

  /* send the message line to the server */
  u_int32_t i = (strstr(req, "\r\n\r\n") + 4) - req;
  n = SSL_write(ssl_server, req, i);
  if (n < 0) {
    printf("(%03d) ssl_get_server_response: ERROR SSL_write returned %d\n", client_fd, n);
    ssl_print_error(ssl_server, n);
    close(server_fd);
    handle_error(client_fd);
  }

  u_int32_t content_length = BUFSIZE + 1;

  bzero(buf, BUFSIZE);
  i = 0;

  n = SSL_read(ssl_server, buf, 1024);

  if (n <= 0) {
    close(server_fd);
    handle_error(client_fd);
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
          is_chunked = true;
        }
      }
    }

    n = SSL_read(ssl_server, buf + i, 1024);

    if (n < 0) {
      close(server_fd);
      handle_error(client_fd);
    }

    i += n;
    
    // If response is chunk encoded, return once we see the final chunk
    if (is_chunked && (strstr(buf, "\r\n0\r\n\r\n") != NULL)) {
      break;
    }
  }

  ssl_close(server_fd, ssl_server, NULL);
  close(server_fd);
  free(arr[0]);
  free(arr[1]);
  free(arr[2]);
  free(arr);
  return buf;
}
