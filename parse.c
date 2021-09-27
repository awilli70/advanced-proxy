/* parse.h - Implementation of http get request         *
 * and response parser                                  *
 * Alexander Williams                                   */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define GETREQ_SIZE 4096
char *getreq = "GET http://www.cs.cmu.edu/~prs/bio.html HTTP/1.1\r\n Host: www.cs.cmu.edu\r\n\r\n";

/* returns arr with [path, host, port (if exists)] */
void **split_request(char *req) {
    char *get_string = "GET ";
    char *host_string = "Host: ";
    char *path = malloc(101 * sizeof(char));
    assert(path != NULL);
    char *host = malloc(101 * sizeof(char));
    assert(host != NULL);
    u_int32_t *port = malloc(sizeof(u_int32_t));
    assert(port != NULL);
    *port = 0;
    u_int32_t i = 0;
    void **arr = malloc(sizeof(void *) * 3);
    assert(arr != NULL);
    char *path_loc = strstr(req, get_string) + 4;
    char *host_loc = strstr(req, host_string) + 6;
    while (*path_loc != ' ') {
        path[i] = *path_loc;
        i++;
        path_loc = path_loc + 1;
    }
    path[i] = '\0';
    i = 0;
    while (*host_loc != ' ' && *host_loc != ':') {
        host[i] = *host_loc;
        i++;
        host_loc = host_loc + 1;
    }
    host[i] = '\0';
    if (*host_loc == ' ') {
        *port = 80;
        arr[0] = path;
        arr[1] = host; 
        arr[2] = port;
        return arr;
    } else {
        host_loc = host_loc + 1;
        while (*host_loc != ' ' && *host_loc != '\r') {
            if (*port > 0) {
                *port = *port * 10;    
            }
            *port = *port + (*host_loc - '0');
            host_loc = host_loc + 1;
        }
        arr[0] = path;
        arr[1] = host; 
        arr[2] = port;
        return arr;
    }
}

int main() {
    void **arr = split_request(getreq);
    u_int32_t *success = arr[2];
    printf("%d\n", *success);
    exit(EXIT_SUCCESS);
}