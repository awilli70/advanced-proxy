/*
 * HTTP proxy with cache
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/time.h>
#include "parse.h"
#include "client.h"
#include "server.h"
#include "cache.h"
#include "error.h"

#define TIMEOUT 3

struct proxy_params {
    int connfd;
    Cache_T c;
    pthread_t *t;
};

struct C
{
    struct Q *objs;
    struct H *refs;
};

pthread_mutex_t lock;

/* handle_connect_req - creates a tunnel between client and server, passing
 *                      data to and from without modification.
 *   args:
 *     - int client_fd
 *     - int server_fd
 *   
 *   returns: 
 *     - none
 * 
 * Uses select() to pass messages back and forth between client and server
 * until one of them disconnects. When one party disconnects, this function 
 * terminates.
 */ 
void handle_connect_req(int client_fd, char *req)
{
    int client_r_fd, server_r_fd, client_w_fd, server_w_fd;
    struct timeval timeout;
    fd_set fdset;
    int max_fd;
    char buf[10000];
    const char *connection_established = "HTTP/1.0 200 Connection established\r\n\r\n";

    ///////////////////////////////
    int server_fd, n, optval;
    int *portno;
    u_int32_t res_sz = 0;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname;
    if (buf == NULL) {
      error("Error allocating buffer");
    }
    void **arr = split_request(req);

    /* socket: create the socket */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) 
        error("ERROR opening socket");

    optval = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, 
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

    ///////////////////////////////

    /* connect: create a connection with the server */
    if (connect(server_fd, &serveraddr, sizeof(serveraddr)) < 0) {
      error("ERROR connecting");
    } else {
      // Connection succesfully established with server
      printf("proxy connected to server\n");
      // Write HTTP 200 message back to client before tunnel is actually made
      n = write(client_fd, connection_established, strlen(connection_established));
      if (n < 0) {
        error("ERROR couldnt write to client");
        // TODO: handle error
      }
      printf("proxy successful sent response to client after connection\n");
    }

    client_r_fd = client_fd;
    server_r_fd = fileno(fdopen(server_fd, "r"));
    client_w_fd = client_fd;
    server_w_fd = fileno(fdopen(server_fd, "w"));
    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;
    
    // Create tunnel to send messages directly between client and server
    while (1) {
        max_fd = client_r_fd >= server_r_fd ? client_r_fd : server_r_fd;

        FD_ZERO( &fdset );
        FD_SET( client_r_fd, &fdset );
        FD_SET( server_r_fd, &fdset );
        n = select( max_fd + 1, &fdset, (fd_set*) 0, (fd_set*) 0, &timeout );
        if ( n == 0 ) {
            // TODO: handle error
            return;
        }
        else if ( FD_ISSET( client_r_fd, &fdset ) )
        {
            // Client has something to say
            n = read( client_r_fd, buf, sizeof( buf ) );
            // TODO: handle error
            // TODO: handle disconnection
            if ( n <= 0 )
                break;
            n = write( server_w_fd, buf, n );

            // TODO: handle error
            if ( n <= 0 )
                break;
        }
        else if ( FD_ISSET( server_r_fd, &fdset ) )
        {
            // Server has something to say
            n = read( server_r_fd, buf, sizeof( buf ) );
            // TODO: handle error
            // TODO: handle disconnection
            if ( n <= 0 )
                break;
            n = write( client_w_fd, buf, n );

            // TODO: handle error
            if ( n <= 0 )
                break;
        }
    }

    // only closing server fds because client_fd is closed after this function
    // is called in proxy_fun
    close(server_r_fd);
    close(server_w_fd);
    close(server_fd);
}

void *proxy_fun(void *args) {
    struct proxy_params *ps = args;
    int connfd = ps->connfd;
    Cache_T c = ps->c;
    pthread_t *currthread = ps->t;
    char *req, *res, *uri;
    char *req_type;
    printf("Starting thread for %d\n", connfd);

    req = read_client_req(connfd);
    req_type = get_req_type(req); // either "CONNECT" or "GET"
    uri = make_uri(split_request(req));
    printf("%s, thread conn %d\n", uri, connfd);

    if (strcmp(req_type, "GET") == 0) {
        // Handle GET request
        printf("GET request\n");
        pthread_mutex_lock(&lock);
        res = cache_get(c, uri);
        pthread_mutex_unlock(&lock);
        if (res == NULL) {
            // response not found in cache --> request from server, cache, send
            res = get_server_response(req);
            if (check_header(res, "max-age=") != NULL) {
                pthread_mutex_lock(&lock);
                cache_put(c, uri, res, parse_int_from_header(res, "max-age="));
                pthread_mutex_unlock(&lock);
            } else {
                pthread_mutex_lock(&lock);
                cache_put(c, uri, res, 3600);
                pthread_mutex_unlock(&lock);
            }
            printf("Fetched %s from server\n", uri);
            write_client_response(connfd, res);
            
        } else {
            // response found in cache --> send back to client w/ new header
            printf("Fetched %s from cache\n", uri);
            res = add_header(res, cache_ttl(c, uri));
            write_client_response(connfd, res);
            free(res);
        }
        printf("GET response sent for socket %d\n", connfd);
    } else if (strcmp(req_type, "CONNECT") == 0) {
        // Handle CONNECT request
        printf("CONNECT request\n");
        handle_connect_req(connfd, req);
    } else {
        error("request not GET or CONNECT");
    }
    free(req);
    free(ps);
    free(uri);
    close(connfd);
    pthread_exit(NULL);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    /* Initial server socket creation */
    int listenfd; /* listening socket */
    struct sockaddr_in serveraddr; /* server's addr */
    int portno = atoi(argv[1]);
    int connfd;
    int optval;
    Cache_T c;
    pthread_t *p;

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) 
        error("ERROR opening socket");

    /* setsockopt: Handy debugging trick that lets 
     * us rerun the server immediately after we kill it; 
     * otherwise we have to wait about 20 secs. 
     * Eliminates "ERROR on binding: Address already in use" error. 
     */
    optval = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, 
	            (const void *)&optval , sizeof(int));
    
    /* build the server's internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET; /* we are using the Internet */
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY); /* accept reqs to any IP addr */
    serveraddr.sin_port = htons((unsigned short)portno); /* port to listen on */

    /* bind: associate the listening socket with a port */
    if (bind(listenfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) 
        error("ERROR on binding");

    /* listen: make it a listening socket ready to accept connection requests */
    if (listen(listenfd, 5) < 0) /* allow 5 requests to queue up */ 
        error("ERROR on listen");
    c = initialize_cache(20);
    pthread_mutex_init(&lock, NULL);
    while(1) {
        connfd = get_client_connfd(listenfd);
        char *buf = malloc(sizeof(char) * 11);
        p = malloc(sizeof(pthread_t));
        struct proxy_params *ps = malloc(sizeof(struct proxy_params));
        ps->c = c;
        ps->connfd = connfd;
        ps->t = p;

        pthread_create(p, NULL, proxy_fun, ps);
    }
}