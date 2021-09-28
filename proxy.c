/*
 * HTTP proxy with cache
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include "parse.h"
#include "client.h"

char *getreq = "GET http://www.cs.cmu.edu/~prs/bio.html HTTP/1.1\r\nHost: www.cs.cmu.edu\r\n\r\n";

int main(int argc, char **argv)
{
    char *c = get_buf(getreq);
    printf("%s", c);
    exit(EXIT_SUCCESS);
}
