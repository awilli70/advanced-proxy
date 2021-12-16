/* parse.h - Implementation of http get request         *
 * and response parser                                  *
 * Alexander Williams                                   */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define GETREQ_SIZE 4096
#define GETRES_SIZE (10 * 1024 * 1024)
#define MAX_URI_LENGTH 2000

/* get_req_type(char *req)
 *   args:
 *     - char *req: HTTP request string as received from client
 *   return:
 *     - char *req_type: "GET" if req is a GET request
 *                       "CONNECT" if req is a CONNECT request
 *                       Otherwise, return NULL
 */
char *get_req_type(char *req) {
  if (strstr(req, "GET ") != NULL) {
    return "GET";
  } else if (strstr(req, "CONNECT ") != NULL) {
    return "CONNECT";
  } else if (strstr(req, "JOIN-") != NULL) {
    return "JOIN";
  } else {
    return NULL;
  }
}

char *get_read_type(char *req) {
  if (get_req_type(req) != NULL) {
    return get_req_type(req);
  } else if (strstr(req, "HTTP") != NULL) {
    return "RES";
  }
}

/* returns arr with [path, host, port (if exists)] */
void **split_request(char *req, bool use_ssl) {
  char *host_string = "Host: ";
  char *path = malloc(MAX_URI_LENGTH * sizeof(char));
  assert(path != NULL);
  char *host = malloc(MAX_URI_LENGTH * sizeof(char));
  assert(host != NULL);

  int *port = malloc(sizeof(int));
  assert(port != NULL);
  *port = 0;
  uint32_t i = 0;
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
    *port = use_ssl ? 443 : 80;
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

  if (end == NULL)
    return NULL;
  *end = '\0';
  ret = strstr(buf, delim);
  *end = '\r';
  return ret;
}

uint32_t parse_int_from_header(char *buf, char *delim) {
  char *it = NULL;
  uint32_t accum = 0;

  it = check_header(buf, delim) + strlen(delim);
  if ((it - strlen(delim)) == NULL)
    return GETRES_SIZE;
  assert((it - strlen(delim)) != NULL);
  while (*it != ' ' && *it != '\r' && *it != ',') {
    accum *= 10;
    accum = accum + (*it - '0');
    it = it + 1;
  }
  return accum;
}

uint32_t get_max_age_from_response(char *res) {
  uint32_t accum = 0;
  char *cache_control_delim = "Cache-Control: ";
  char *max_age_delim = "max-age=";
  char *cache_control_line = check_header(res, cache_control_delim);
  // No Cache-Control line in header
  if (cache_control_line == NULL)
    return 3600;

  char *cache_control_end = strstr(cache_control_line, "\r\n");
  *cache_control_end = '\0';

  // No max-age in Cache-Control line
  if (strstr(cache_control_line, max_age_delim) == NULL)
    return 3600;

  *cache_control_end = '\r';

  // Get max_age (accum) starting from substring "max-age="
  char *max_age_s = strstr(cache_control_line, max_age_delim) + strlen(max_age_delim);
  while (*max_age_s != ' ' && *max_age_s != '\r' && *max_age_s != ',') {
    accum *= 10;
    accum = accum + (*max_age_s - '0');
    max_age_s = max_age_s + 1;
  }

  return accum;
}

char *make_uri(void **req_arr) {
  char *uri = malloc(sizeof(char) * 200);
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

char *add_header(char *buf, uint32_t ttl) {
  char *res = malloc((sizeof(char) * GETRES_SIZE));
  char *header_end = strstr(buf, "\r\n\r\n");
  char *insert = "\r\nAge: ";
  char ttlstring[20];
  int32_t bytes_remaining;

  assert(res != NULL);
  bzero(res, GETRES_SIZE);
  strncpy(res, buf, (header_end - buf));
  sprintf(ttlstring, "%d", ttl);
  (void)strncpy(res + strlen(res), insert, strlen(insert));
  (void)strncpy(res + strlen(res), ttlstring, strlen(ttlstring));
  (void)strncpy(res + strlen(res), "\r\n\r\n", strlen("\r\n\r\n"));
  if (strstr(res, "Content-Length: ") != NULL) {
    bytes_remaining = parse_int_from_header(res, "Content-Length: ");
  } else if (strstr(res, "Transfer-Encoding:") != NULL &&
             strstr(res, "chunked") != NULL) {
    uint32_t header_length = (strstr(res, "\r\n\r\n") + 4) - res;
    bytes_remaining = strstr(res, "\r\n0\r\n\r\n") + 7 - header_length - res;
    if (bytes_remaining - 7 + header_length + res == NULL)
      bytes_remaining = -1;
  } else {
    return NULL;
  }
  if (bytes_remaining >= 0) {
    memcpy(res + strlen(res), buf + (header_end + 4 - buf), bytes_remaining);
  } else {
    memcpy(res + strlen(res), buf + (header_end + 4 - buf),
           GETRES_SIZE - ((strstr(res, "\r\n\r\n") + 4) - res));
  }
  return res;
}