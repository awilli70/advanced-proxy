/* parse.h - Implementation of http get request         *
 * and response parser                                  *
 * Alexander Williams                                   */

#ifndef PARSER_INCLUDED
#define PARSER_INCLUDED

#include <stdlib.h>

/* returns arr with [path, host, port (if exists)] */
extern void **split_request(char *);
extern u_int32_t parse_int_from_header(char *, char *);
extern char *make_uri(void **);
extern char *add_header(char *, u_int32_t);

#endif