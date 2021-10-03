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
#include "parse.h"
#include "client.h"
#include "server.h"
#include "cache.h"

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
    char *req, *res, *uri;
    Cache_T c;

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
    c = initialize_cache(10);
    while(1) {
        connfd = get_client_connfd(listenfd);
        req = read_client_req(connfd);
        uri = make_uri(split_request(req));
        res = cache_get(c, uri);
        if (res == NULL) {
            res = get_server_response(req);
            if (check_header(res, "max-age=") != NULL) {
                cache_put(c, uri, res, parse_int_from_header(res, "max-age="));
            } else {
                cache_put(c, uri, res, 3600);
            }
            printf("Fetched %s from server\n", uri);
            write_client_response(connfd, res);
        } else {
            printf("Fetched %s from cache\n", uri);
            res = add_header(res, cache_ttl(c, uri));
            write_client_response(connfd, res);
            free(res);
        }
        printf("Response Sent\n");
        free(req);
        close(connfd);
    }
}