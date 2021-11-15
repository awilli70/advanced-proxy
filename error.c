/* Error.c - Implementation of error handling */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "error.h"


/* 
 * error - wrapper for perror
 */
void error(char *msg) {
    perror(msg);
    exit(0);
}

void invalid_hostname(char *hostname) {
    char msg[] = "ERROR, no such host as ";
    strcat(msg, hostname);
    strcat(msg, ".\n");
    error(msg);
}

