/* parse.h - Implementation of http get request         *
 * and response parser                                  *
 * Alexander Williams                                   */

#ifndef PARSER_INCLUDED
#define PARSER_INCLUDED

/* returns arr with [path, host, port (if exists)] */
extern void **split_request(char *);

#endif