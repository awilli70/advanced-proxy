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
void handle_error(int socket, pthread_t thread)
{
    printf("Handling error on socket %d\n", socket);
    close(socket);
    printf("socket %d closed\n", socket);
    pthread_cancel(thread);
}

void invalid_hostname(char *hostname) {
    char msg[] = "ERROR, no such host as ";
    strcat(msg, hostname);
    strcat(msg, ".\n");
    error(msg);
}

