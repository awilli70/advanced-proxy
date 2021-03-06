/* parse.h - Implementation of http get request         *
 * and response parser                                  *
 * Alexander Williams                                   */

#ifndef PARSER_INCLUDED
#define PARSER_INCLUDED

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
/* get_req_type(char *req)
 *   args: 
 *     - char *req: HTTP request string as received from client
 *   return:
 *     - char *: "GET" if req is a GET request
 *               "CONNECT" if req is a CONNECT request
 *               Otherwise, error
 */
char *get_req_type(char *);
/* determines if char * is a response, GET, CONNECT, or none */
char *get_read_type(char *);

/* split_request(char *req) 
 *   args:
 *     - char *req: HTTP request string as received from client
 *   return:
 *     - void **: array with [path, host, port (if exists)] 
 */
extern void **split_request(char *, bool);
extern u_int32_t parse_int_from_header(char *, char *);
uint32_t get_max_age_from_response(char *);
extern char *make_uri(void **);
extern char *add_header(char *, uint32_t);
extern char *check_header(char *, char *);

#endif