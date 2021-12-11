#include <openssl/ssl.h>

#define KEY_FILE "key_cert.pem"
#define CERT_FILE "key_cert.pem"
#define TRUST_CERT_FILE "cacert.pem"

int ssl_password_cb(char* buf, int num, int rwflag, void* userdata);
int ssl_check_cert(SSL* ssl);
void ssl_sigpipe_handle(int x);
SSL_CTX *ssl_init_context(char *key_file, char *cert_file); 
void ssl_close(int socket, SSL *ssl, BIO* b_io);
void ssl_print_error(SSL *ssl, int err);
void ShowCerts(SSL* ssl);
