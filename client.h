#ifndef CLIENT_INCLUDED
#define CLIENT_INCLUDED

/* returns buf from target */
extern char *get_server_response(int, char *);
void error(char *);

#endif