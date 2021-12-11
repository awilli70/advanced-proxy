/* echo_client.c
   
   Simple SSL Echo Server and Client
   15-441 Networks, Fall 2002
   
   Justin Weisz (jweisz@andrew.cmu.edu)
   
   Created: 07/23/02
*/


// Header Files --------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/ssl.h>

#include "ssl_common.h"


// Function Definitions ------------------------------------------------------


// main -----------------------------------------------------------------------
int main( int argc, char *argv[] ) {
    /* server variables:
        ipAddress     - the IP address of the server to connect to, specified
                        on the command line
        port          - the port number to connect to, also specified on the
                        command line
        connectSocket - the socket used to communicate with the server
        serverAddress - the address of the server
    */
    char                ipAddress[16];
    int                 port;
    int                 connectSocket;
    struct sockaddr_in  serverAddress;
    
    
    /* SSL variables:
        ssl_connection - an SSL object representing the SSL connection
        ssl_context    - the SSL context, keeps track of our private key
                         as well as the certificate authorities we trust
        ssl_server_bio - buffered I/O object for reading and writing to
                         the server
    */
    SSL*                ssl_connection;
    SSL_CTX*            ssl_context;
    BIO*                ssl_server_bio;
        
    /* misc variables */
    char                buf[kBufferSize];
    char                c;
    int                 pos;
    int                 dataTransmitted;
    
    
    /* Make sure that we have the right number of command line arguments. */
    if ( argc < 3 ) {
        printf("%s: [ip address] [port number]\n", argv[0]);
        exit(0);
    }
    
    // read in the IP address specified on the command line
    ipAddress[0] = '\0';
    strncpy(ipAddress, argv[1], 16);
    
    // read in the port number specified on the command line
    port = atoi(argv[2]);
    
    
    // initialize the SSL library
    SSL_load_error_strings();   /* readable error messages */
    SSL_library_init();         /* initialize library */
    
    // make the SSL context
    // we specify NULL as the first argument, since the client does not have
    // (and does not need) a private key, and we specify the server's keyfile
    // as the second argument since we have to explicitly trust the server,
    // otherwise we cannot connect to it
    ssl_context = ssl_initialize_context( NULL, SERVER_KEYFILE );
    
    
    // set up the socket for listening
    connectSocket = socket( AF_INET, SOCK_STREAM, 0 );
    if ( connectSocket < 0 )
        FatalError( "ERROR opening socket, terminating\n" );
    
    
    // set up the server address
    // inet_addr() converts a string IP address to an integer (4 byte)
    // IP address
    bzero( (char *)&serverAddress, sizeof(serverAddress) );
    
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = inet_addr( ipAddress );
    serverAddress.sin_port = htons( port );
    
    
    // set up our SSL context and buffered I/O object
    ssl_connection = SSL_new(ssl_context);
    ssl_server_bio = BIO_new_socket(connectSocket, BIO_NOCLOSE);
    SSL_set_bio( ssl_connection, ssl_server_bio, ssl_server_bio );
    
    
    // connect to the server
    if (connect(connectSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        printf("ERROR connecting, terminating\n");
        exit(1);
    }
    
    
    /* Once we connect to the server, we need to start the SSL handshake.
    Note that at this point, the server will be calling SSL_accept() */
    if ( SSL_connect(ssl_connection) <= 0 )
        FatalError("ERROR in SSL_connect\n");
    
    
    // verify that the server has a valid certificate
    ssl_check_cert(ssl_connection);
    
    // we have now made an SSL connection!
    printf("Connected to %s:%d\n", ipAddress, port);
    
    /* Here we read in a single line from the console (terminated by '\n'), and
    send it to the server.  Since this is an echo server, it will send back what
    we sent it, so we have to read that back in.  We keep looping until the user
    types in a control-d character (hex 0xFF). */
    // do {
        bzero(buf, kBufferSize);
        char *req = "GET /echo HTTP/2\r\nHost: reqbin.com\r\nUser-Agent: curl/7.55.1\r\nAccept: */*\r\n\r\n\r\n"; 
        // char *req = "GET /~dga/dga-headshot.jpg HTTP/1.1\r\nHost: www.cs.cmu.edu\r\nUser-Agent: curl/7.55.1\r\nAccept: */*\r\n\r\n"; 
        memcpy(buf, req, strlen(req)); // "GET https://reqbin.com/echo HTTP/1.1\r\n\r\n";
        // pos = 0;
        // do {
        //     printf("getchar\n");
        //     c = getchar();
        //     buf[pos++] = c;
                
        //     if ( c == (char)0xFF )
        //         break;
        // } while ( c != '\n' );
        
        // dataTransmitted = BIO_write(ssl_server_bio, buf, strlen(buf));
        // BIO_flush(ssl_server_bio);
        dataTransmitted = SSL_write(ssl_connection, buf, strlen(buf));
        
        if ( buf[0] != (char)0xFF ) {
            bzero(buf, kBufferSize);
            // dataTransmitted = BIO_read(ssl_server_bio, buf, kBufferSize);
            dataTransmitted = SSL_read(ssl_connection, buf, kBufferSize);
            
            printf("Received %d bytes:\n%s\n", dataTransmitted, buf);
        }
    // } while (buf[0] != (char)0xFF);
    
    
    /* Time to shut down the SSL connection.  ssl_connection is freed here. */
    ssl_close_connection( connectSocket, ssl_connection, ssl_server_bio );
    
    
    /* Destroy the SSL context. */
    ssl_destroy_context(ssl_context);
    
    
    /* Finally, close the socket to the client */
    close(connectSocket);
    
    return 0;
}

