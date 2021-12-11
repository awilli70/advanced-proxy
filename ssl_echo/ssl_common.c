/* ssl_common.c
   
   Simple SSL Echo Server and Client
   15-441 Networks, Fall 2002
   
   Justin Weisz (jweisz@andrew.cmu.edu)
   
   Created: 07/23/02
*/


// Headers --------------------------------------------------------------------

#include <signal.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ssl_common.h"


// Globals --------------------------------------------------------------------

BIO*    bio_err;


// Function Definitions -------------------------------------------------------


// ssl_sigpipe_handle ---------------------------------------------------------
void ssl_sigpipe_handle( int x ) {
    /* Ignore broken pipes */
}


// ssl_password_cb ------------------------------------------------------------
int ssl_password_cb( char* buf, int num, int rwflag, void* userdata ) {
    return 0;
}


// ssl_initialize_context -----------------------------------------------------
SSL_CTX* ssl_initialize_context( char* keyfile, char* ca ) {
    /* variables:
        method  - determines what SSL method we use
                  here we use SSLv3
        context - the SSL context we are creating
    */
    SSL_METHOD* method;
    SSL_CTX*    context;
    
    /* bio_err is a buffered I/O object which we will use for writing error 
    messages to stderr */
    if ( !bio_err ) {
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    }
    
    /* Ignore broken pipes which would cause our program to terminate 
    prematurely */
    signal(SIGPIPE, ssl_sigpipe_handle);
    
    /* Create the actual SSL context.
    Here is where we specify what version of SSL we want to use.  We could 
    choose from SSLv2, SSLv3, SSLv2 or 3, or TLSv1.  For this example, and for 
    your web server, we will be using SSLv3. */
    method = SSLv3_method();
    context = SSL_CTX_new(method);
    
    if ( keyfile != NULL ) {
        /* Load our keys and certificates */
        if ( !(SSL_CTX_use_certificate_chain_file(context, keyfile)) )
            FatalError("Can't read certificate file");
        
        /* If our private key is encrypted, then the password callback is used to
        get the password to decrypt the file.  Our private key is not encrypted,
        so this is not used. */
        SSL_CTX_set_default_passwd_cb(context, ssl_password_cb);
        if ( !(SSL_CTX_use_PrivateKey_file(context, keyfile, SSL_FILETYPE_PEM)) )
            FatalError("Can't read key file");
    }
    
    /* Load the Certificate Authorities we trust.  In this case, we are going 
    to trust that ``server.pem" is the CA.  Otherwise, we wouldn't be able to
    establish a connection, since we don't explicitly trust anyone!  */
    if ( !(SSL_CTX_load_verify_locations(context, ca, 0)) )
        FatalError("Can't read CA list");
            
    return context;
}


// ssl_destroy_context --------------------------------------------------------
void ssl_destroy_context( SSL_CTX* context ) {
    SSL_CTX_free(context);
}


// ssl_check_cert -------------------------------------------------------------
int ssl_check_cert(SSL* ssl) {
    return (SSL_get_verify_result(ssl) == X509_V_OK);
}


// ssl_close_connection -------------------------------------------------------
void ssl_close_connection( int socket, SSL* ssl, BIO* bio ) {
    int ssl_error_code;
    
    /* If we were the first party to call SSL_shutdown(), then we will get a
    return value of '0'.  So, we try again, but first we send a TCP FIN to
    trigger the other side's close_notify state. */
    
    ssl_error_code = SSL_shutdown(ssl);
    
    if ( !ssl_error_code ) {
        fprintf(stderr, "Forcing shutdown of socket\n");
        shutdown( socket, 1 );
        ssl_error_code = SSL_shutdown(ssl);
    }
    
    switch (ssl_error_code) {
        case 1:
            fprintf(stderr, "Shutdown successful\n");
        break;
        
        case 0:
        case -1:
        default:
            fprintf(stderr, "Error shutting down SSL connection:\n");
            SSL_Error(ssl, ssl_error_code);
        break;
    }
    
    // free memory
    SSL_free(ssl);
}


// FatalError -----------------------------------------------------------------
void FatalError( char* str ) {
    /* Print out the error message, flush the SSL error buffer, and exit */
    BIO_printf(bio_err, "%s\n", str);
    ERR_print_errors(bio_err);
    exit(1);
}


// SSL_Error ------------------------------------------------------------------
void SSL_Error( SSL* ssl, int ssl_error_code ) {
    switch (SSL_get_error(ssl, ssl_error_code)) {
        case SSL_ERROR_NONE:
            fprintf(stderr, "SSL_ERROR_NONE\n");
        break;
        case SSL_ERROR_ZERO_RETURN:
            fprintf(stderr, "SSL_ERROR_ZERO_RETURN\n");
        break;
        case  SSL_ERROR_WANT_READ:
            fprintf(stderr, "SSL_ERROR_WANT_READ\n");
        break;
        case SSL_ERROR_WANT_WRITE:
            fprintf(stderr, "SSL_ERROR_WANT_WRITE\n");
        break;
        case SSL_ERROR_SYSCALL:
            fprintf(stderr, "SSL_ERROR_SYSCALL: %d\n", ssl_error_code);
        break;
        case SSL_ERROR_SSL:
            fprintf(stderr, "SSL_ERROR_SSL\n");
        break;
        default:
            fprintf(stderr, "Unknown!\n");
        break;
    }
    
    fprintf(stderr, "SSL error queue:\n");
    ERR_print_errors(bio_err);
}


// SSL_FatalError -------------------------------------------------------------
void SSL_FatalError( SSL* ssl, int ssl_error_code ) {
    SSL_Error(ssl, ssl_error_code);
    exit(1);
}
