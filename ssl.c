#include "cache.h"
#include "client.h"
#include "error.h"
#include "parse.h"
#include "server.h"
#include <signal.h>
#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// #define CERT_FILE "key_cert.pem"
// #define KEY_FILE "key_cert.pem"

// BIO *bio_err;
// sslv23_client_method() for connecting to server

int ssl_password_cb( char* buf, int num, int rwflag, void* userdata ) {
    return 0;
}

// int ssl_check_cert(SSL* ssl) {
//     return (SSL_get_verify_result(ssl) == X509_V_OK);
// }

int ssl_check_cert(SSL* ssl) {
    if (!SSL_get_peer_certificate(ssl)) {
        printf("ERROR getting server peer certificate\n");
        return 0;
    }

    return (SSL_get_verify_result(ssl) == X509_V_OK);
}

void ssl_sigpipe_handle(int x) {}

SSL_CTX *ssl_init_context(char *key_file, char *cert_file) 
{
    SSL_METHOD* method = SSLv23_method(); //TLSv1_2_method();
    SSL_CTX*    context = SSL_CTX_new(method);
    if (!SSL_CTX_set_default_verify_paths(context)) {
        printf("Error trusting CAs\n");
    }

    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(context, 4);

    // puts(X509_get_default_cert_file());

    // if (!bio_err) {
    //     bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    // }


    signal(SIGPIPE, ssl_sigpipe_handle);

    if (key_file != NULL) {
        // Load keys and certificates
        if (!(SSL_CTX_use_certificate_chain_file(context, key_file))) 
            error("ERROR opening certificate file");
        
        SSL_CTX_set_default_passwd_cb(context, ssl_password_cb);
        if (!(SSL_CTX_use_PrivateKey_file(context, key_file, SSL_FILETYPE_PEM)))
            error("ERROR opening key file");
    }

    if (!(SSL_CTX_load_verify_locations(context, cert_file, 0)))
        error("ERROR reading certificate authority list");

    return context;
}

void ssl_close(int socket, SSL *ssl, BIO* b_io)
{
    int error_code;

    error_code = SSL_shutdown(ssl);

    if (!error_code) {
        printf("SSL forcing shutdown\n");
        shutdown(socket, 1);
        error_code = SSL_shutdown(ssl);
    }

    switch (error_code) {
        case 1:
            printf("SSL shutdown successful\n");
            break;
        case 0:
        case -1:
        default:
            printf("Error shutting down SSL connections\n");
    }

    SSL_free(ssl);
}

void ssl_print_error(SSL *ssl, int err)
{
    int e = SSL_get_error(ssl, err);
    printf("ssl_print_error: SSL_get_error returned %d\n", e);
    printf("ssl_print_error: ");
    switch (e) {
    case SSL_ERROR_SSL:
        printf("ssl\n");
        // ERR_print_errors(ssl_client_b_io);
        ERR_print_errors_fp(stdout);
        break;
    case SSL_ERROR_WANT_ACCEPT:
        printf("want accept\n");
        break;
    case SSL_ERROR_SYSCALL:
        printf("syscall\n");
        ERR_print_errors_fp(stdout);
        break;
    case SSL_ERROR_WANT_CONNECT:
        printf("want connect\n");
        break;
    case SSL_ERROR_WANT_READ:
        printf("want read\n");
        break;
    case SSL_ERROR_WANT_WRITE:
        printf("want write\n");
        break;
    case SSL_ERROR_WANT_X509_LOOKUP:
        printf("want x509 lookup\n");
        break;
    case SSL_ERROR_ZERO_RETURN:
        printf("zero return\n");
        break;
    case SSL_ERROR_NONE:
        printf("none\n");
        break;
    default:
        printf("default\n");
    }
}

void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}