#ifndef SERVER_INCLUDED
#define SERVER_INCLUDED

/* returns buf from target */
extern int get_client_connfd(int);
extern char *read_client_req(int);
extern void write_client_response(int, char *);


#endif