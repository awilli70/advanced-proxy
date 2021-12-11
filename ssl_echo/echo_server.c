/* echo_server.c
   
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

#include <netinet/in.h>
#include <netdb.h>

#include <openssl/ssl.h>

#include "ssl_common.h"


// Function Definitions -------------------------------------------------------


// main -----------------------------------------------------------------------
int main( int argc, char *argv[] ) {
    /* server variables:
        listenSocket  - the socket used to listen for incoming connections
        portNumber    - the port number the server runs on, default of 1234
        optVal        - used in setsockopt()
        serverAddress - the address of the server
    */
    int                 listenSocket;
    int                 portNumber = kDefaultPort;
    int                 optVal;
    struct sockaddr_in  serverAddress;
    
    /* client variables:
        clientSocket  - the socket used for reading data from the client
        clientLength  - used in accept()
        clientAddress - the address of the client
    */
    int                 clientSocket;
    int                 clientLength;
    struct sockaddr_in  clientAddress;
    
    
    /* SSL variables:
        ssl_connection - an SSL object representing the SSL connection
        ssl_context    - the SSL context, keeps track of our private key
                         as well as the certificate authorities we trust
        ssl_client_bio - buffered I/O object for reading and writing to
                         the client
        ssl_error_code - used to see if the ssl functions return errors
    */
    SSL*                ssl_connection;
    SSL_CTX*            ssl_context;
    BIO*                ssl_client_bio;
    int                 ssl_error_code;
    
    /* misc variables */
    char                buf[kBufferSize];
    int                 dataTransmitted;
    
    
    // initialize the SSL library
    SSL_load_error_strings();   /* readable error messages */
    SSL_library_init();         /* initialize library */
    
    // make the SSL context
    // we specify our keyfile twice here, the first is so we actually load our
    // private key, and the second is so we trust ourselves explicitly as a
    // certificate authority
    ssl_context = ssl_initialize_context( SERVER_KEYFILE, SERVER_KEYFILE );
    
    
    // set up the socket for listening
    listenSocket = socket( AF_INET, SOCK_STREAM, 0 );
    if ( listenSocket < 0 )
        FatalError( "ERROR opening socket, terminating\n" );
    
    
    // allow us to restart server immediately
    // this prevents bind() from failing if you try to run your program twice 
    // in a row
    optVal = 1;
    setsockopt( listenSocket, SOL_SOCKET, SO_REUSEADDR, (const void *)&optVal, sizeof(int) );
    
    
    // set up the server address
    bzero( (char *)&serverAddress, sizeof(serverAddress) );
    
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl( INADDR_ANY );
    serverAddress.sin_port = htons( portNumber );
    
    
    // bind the socket to our address
    if ( bind(listenSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0 )
        FatalError( "ERROR on binding, terminating\n" );
    
    
    // get ready to accept connection requests
    if ( listen( listenSocket, kMaxRequestsQueue ) < 0 )
        FatalError( "ERROR on listen, terminating\n" );
    
    
    // this is used to tell accept() how big the client address is
    clientLength = sizeof(struct sockaddr_in);
    
    
    // we are now ready to start accepting connections
    printf( "SSL Echo server started on port %d\n", portNumber );
    printf( "Awaiting connections...\n" );
    
    
    // main loop: accept a connection, read in data, echo it back, disconnect
    // note that this can only handle one client at a time
    while (1) {
        // wait for a connection request
        clientSocket = accept( listenSocket, (struct sockaddr *)&clientAddress, &clientLength );
        if (clientSocket < 0) {
            FatalError( "ERROR on accept, terminating\n" );
        }
        
        
        /* Here we make a new buffered I/O object attached to the client's 
        socket which will be used for reading and writing to the client.  We
        also make a new SSL connection, and attach the BIO object to that 
        connection. */
        ssl_client_bio = BIO_new_socket( clientSocket, BIO_NOCLOSE );
        ssl_connection = SSL_new( ssl_context );
        SSL_set_bio( ssl_connection, ssl_client_bio, ssl_client_bio );
        printf("SSL connection accepted!\n");
        
        
        /* After we accept the connection using accept(), we call SSL_accept() 
        to do the actual SSL handshake. */
        if ( (ssl_error_code = SSL_accept(ssl_connection)) <= 0) {
            FatalError("ERROR in SSL_accept");
        }
        
        
        /* Now that our communications are secure, we begin the echo process.
        We read in data from the ssl_client_bio object, and send it back to the
        client.  We terminate when the client sends a control-d character
        (hex 0xFF). */
        do {
            // zero out our buffer
            bzero(buf, kBufferSize);
            
            // read in from the client
            dataTransmitted = BIO_read( ssl_client_bio, buf, kBufferSize );
            
            printf("recieved data: %s", buf);
            
            if ( buf[0] != (char)0xFF ) {
                dataTransmitted = BIO_write( ssl_client_bio, buf, strlen(buf));
                BIO_flush(ssl_client_bio);
            }
        } while ( (buf[0] != (char)0xFF) && (dataTransmitted > 0) );
        
        
        /* Time to shut down the SSL connection.  ssl_connection is freed
        here. */
        ssl_close_connection( clientSocket, ssl_connection, ssl_client_bio );
        
    
        /* Close the socket to the client */
        close(clientSocket);
    }
    
        
    /* Free the SSL context, since we're finished making SSL 
    connections for good now. */
    ssl_destroy_context(ssl_context);
        
    return 0;
}

