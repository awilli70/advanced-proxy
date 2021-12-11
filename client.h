#include <openssl/ssl.h>

#ifndef CLIENT_INCLUDED
#define CLIENT_INCLUDED

/* returns buf from target */
extern char *get_server_response(int, char *);
extern char* ssl_get_server_response(SSL *ssl_client, SSL *ssl_server, int client_fd, char *req);
void error(char *);

#endif