/* parse.h - Implementation of http get request         *
 * and response parser                                  *
 * Alexander Williams                                   */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define GETREQ_SIZE 4096
#define GETRES_SIZE (10 * 1024 * 1024)

/* get_req_type(char *req)
 *   args: 
 *     - char *req: HTTP request string as received from client
 *   return:
 *     - char *req_type: "GET" if req is a GET request
 *                       "CONNECT" if req is a CONNECT request
 *                       Otherwise, return NULL
 */
char *get_req_type(char *req)
{
    if (strstr(req, "GET ") != NULL) {
        return "GET";
    }
    else if (strstr(req, "CONNECT ") != NULL) {
        return "CONNECT";
    }
    else {
        return NULL;
    }
}

/* returns arr with [path, host, port (if exists)] */
void **split_request(char *req) {
    // char *get_string = "GET ";
    // ^ commented this out because seems like its never used
    char *host_string = "Host: ";
    char *path = malloc(101 * sizeof(char));
    assert(path != NULL);
    char *host = malloc(101 * sizeof(char));
    assert(host != NULL);
    int *port = malloc(sizeof(int));
    assert(port != NULL);

    *port = 0;
    u_int32_t i = 0;
    void **arr = malloc(sizeof(void *) * 3);
    assert(arr != NULL);
    char *path_loc;
    
    // Get host url (without port)
    char *host_loc = strstr(req, host_string) + 6;
    while ((*host_loc != ' ' && *host_loc != ':') && 
                (*host_loc != '\r' && *host_loc != '\n')) {
        host[i] = *host_loc;
        i++;
        host_loc = host_loc + 1;
    }
    host[i] = '\0';

    // Get path (following host url)
    i = 0;
    path_loc = strstr(req, host) + strlen(host);
    if (path_loc == NULL) {
        path_loc = strstr(req, "/");
    }
    while (*path_loc != ' ' && *path_loc != ':') {
        path[i] = *path_loc;
        i++;
        path_loc = path_loc + 1;
    }
    path[i] = '\0';

    // Get port number
    if (*host_loc == ' ' || *host_loc == '\r') {
        // No port is specified after host url
        *port = 80;
        arr[0] = path;
        arr[1] = host; 
        arr[2] = port;
        return arr;
    } else {
        // port is specified after host url (following the ':' char)
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

char *check_header(char *buf, char *delim) {
    char *end = strstr(buf, "\r\n\r\n");
    char *ret = NULL;

    if (end == NULL) return NULL;
    *end = '\0';
    ret = strstr(buf, delim);
    *end = '\r';
    return ret;
}

u_int32_t parse_int_from_header(char *buf, char *delim) {
    char *it = NULL;  
    u_int32_t accum = 0;

    it = check_header(buf, delim) + strlen(delim);
    if ((it - strlen(delim)) == NULL) return GETRES_SIZE;
    assert((it - strlen(delim)) != NULL);
    while (*it != ' ' && *it != '\r') {
        if (accum > 0) {
            accum *= 10;
        }
        accum = accum + (*it - '0');
        it = it + 1;
    }
    return accum;
}

char *make_uri(void **req_arr) {
    char *uri = malloc(200);
    int *port = req_arr[2];
    char *host = req_arr[1];
    char *path = req_arr[0];
    char portstr[10];

    assert(uri != NULL);
    sprintf(portstr, "%d", *port);
    assert(uri != NULL);
    uri = strcpy(uri, host);
    uri = strcat(uri, ":");
    uri = strcat(uri, portstr);
    uri = strcat(uri, path);
    free(req_arr[0]);
    free(req_arr[1]);
    free(req_arr[2]);
    free(req_arr);
    return uri;
}

char *add_header(char *buf, u_int32_t ttl) {
    char *req = malloc((sizeof(char) * GETRES_SIZE));
    char *header_end = strstr(buf, "\r\n\r\n");
    char *insert = "\r\nAge: ";
    char ttlstring[20];
    u_int32_t bytes_remaining;

    assert(req != NULL);
    bzero(req, GETRES_SIZE);
    strncpy(req, buf, (header_end - buf));
    sprintf(ttlstring, "%d", ttl);
    (void) strncpy(req + strlen(req), insert, strlen(insert));
    (void) strncpy(req + strlen(req), ttlstring, strlen(ttlstring));
    (void) strncpy(req + strlen(req), "\r\n\r\n", strlen("\r\n\r\n"));
    bytes_remaining = parse_int_from_header(req, "Content-Length: ");
    memcpy(req + strlen(req), buf + (header_end + 4 - buf), bytes_remaining);
    return req;
}