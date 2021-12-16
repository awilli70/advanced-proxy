/* Error.c - Implementation of error handling */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "error.h"


/* 
 * error - wrapper for perror
 */
void error(char *msg) {
    perror(msg);
    exit(0);
}

/* handle_error
 * 
 * Gracefully close socket and thread, keep proxy running.
 */
void handle_error(int socket)
{
    printf("(%03d) HANDLING ERROR: closing socket and exiting thread\n", socket);
    close(socket);
    pthread_exit(NULL);
}

void invalid_hostname(char *hostname) {
    char msg[] = "ERROR, no such host as ";
    strcat(msg, hostname);
    strcat(msg, ".\n");
    error(msg);
}

