/* Error.h - Implementation of error handling */

#ifndef ERROR_INCLUDED
#define ERROR_INCLUDED

void error(char *msg);
void handle_error(int socket, pthread_t thread);
void invalid_hostname(char *hostname);

#endif