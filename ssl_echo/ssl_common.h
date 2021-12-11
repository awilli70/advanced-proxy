/* ssl_common.h
   
   Simple SSL Echo Server and Client
   15-441 Networks, Fall 2002
   
   Justin Weisz (jweisz@andrew.cmu.edu)
   
   Created: 07/23/02
*/


#ifndef __SSL_COMMON__
#define __SSL_COMMON__


// Constants ------------------------------------------------------------------

#define kMaxRequestsQueue       5
#define kBufferSize             1024
#define	kDefaultPort            1234

#define SERVER_KEYFILE          "server.pem"


// Function Prototypes --------------------------------------------------------

void            ssl_sigpipe_handle      ( int x );
int             ssl_password_cb         ( char* buf, int num, int rwflag, void* userdata );
SSL_CTX*        ssl_initialize_context  ( char* keyfile, char* ca );
void            ssl_destroy_context     ( SSL_CTX* context );

int             ssl_check_cert          ( SSL* ssl );

void            ssl_close_connection    ( int socket, SSL* ssl, BIO* bio );

void            FatalError              ( char* str );
void            SSL_Error               ( SSL* ssl, int ssl_error_code );
void            SSL_FatalError          ( SSL* ssl, int ssl_error_code );


#endif  // __SSL_COMMON__
