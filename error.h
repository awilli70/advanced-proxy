/* Error.h - Implementation of error handling */

#ifndef ERROR_INCLUDED
#define ERROR_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include "parse.h"
#include "error.h"
#include "ssl.h"
#include <assert.h>
#include <openssl/ssl.h>

void error(char *msg);
void handle_error(int socket);
void invalid_hostname(char *hostname);

#endif