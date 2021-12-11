/*
 * HTTP proxy with cache
 * TODO: Error handling when node goes down
 */
#include "cache.h"
#include "client.h"
#include "error.h"
#include "parse.h"
#include "server.h"
#include "ssl.h"
#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define TIMEOUT 3
#define BUFSIZE (10 * 1024 * 1024)
#define CONNECT_INIT_RESPONSE "HTTP/1.1 200 OK\r\n\r\n"
#define FORBIDDEN_RESPONSE "HTTP/1.1 403 Forbidden\r\n\r\n"

struct __attribute__((__packed__)) NodeData {
  char hostname[15];
  unsigned short port;
};

struct proxy_params {
  int connfd;
  uint32_t *nodeflags;
  uint32_t *nodemask;
  int *node_fds;
  Cache_T c;
  pthread_t *t;
  struct NodeData *node_conn_info;
  void **cf;
};

struct node_params {
  int fd;
  int idx;
  Cache_T c;
  int *node_fds;
  uint32_t *nodeflags;
};

struct __attribute__((__packed__)) Bootstrap {
  uint32_t flag;
  uint32_t mask;
  uint32_t sender_mask;
  struct NodeData nodes[32];
};

struct __attribute__((__packed__)) Join {
  char join_str[5];
  char local_hostname[15];
  unsigned short local_port;
  char end_str[5];
};

struct C {
  struct Q *objs;
  struct H *refs;
};

pthread_mutex_t lock;
pthread_mutex_t fd_lock;
pthread_mutex_t read_locks[32];
pthread_cond_t read_conds[32];
char *resbufs[32];

/* handle_connect_req - creates a tunnel between client and server, passing
 *                      data to and from without modification.
 *   args:
 *     - int client_fd
 *     - int server_fd
 *
 *   returns:
 *     - none
 *
 * Uses select() to pass messages back and forth between client and server
 * until one of them disconnects. When one party disconnects, this function
 * terminates.
 */
void handle_connect_req(int client_fd, char *req) {
  int client_r_fd, server_r_fd, client_w_fd, server_w_fd;
  struct timeval timeout;
  fd_set fdset;
  int max_fd;
  char *buf = malloc(sizeof(char) * BUFSIZE);
  assert(buf != NULL);

  int server_fd, n, optval;
  int *portno;
  uint32_t res_sz = 0;
  struct sockaddr_in serveraddr;
  struct hostent *server;
  char *hostname;
  void **arr = split_request(req);

  /* socket: create the socket */
  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    handle_error(client_fd, pthread_self());
  }

  optval = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
             sizeof(int));

  /* gethostbyname: get the server's DNS entry */
  hostname = arr[1];
  server = gethostbyname(hostname);
  if (server == NULL) {
    // invalid_hostname(hostname);
    close(server_fd);
    close(client_fd);
    pthread_exit(NULL);
    // handle_error(client_fd, pthread_self());
  }
  portno = arr[2];
  /* build the server's Internet address */
  bzero((char *)&serveraddr, sizeof(serveraddr));
  serveraddr.sin_family = AF_INET;
  bcopy((char *)server->h_addr, (char *)&serveraddr.sin_addr.s_addr,
        server->h_length);
  serveraddr.sin_port = htons(*portno);

  /* connect: create a connection with the server */
  if (connect(server_fd, &serveraddr, sizeof(serveraddr)) < 0) {
    close(server_fd);
    handle_error(client_fd, pthread_self());
  } else {
    // Connection succesfully established with server
    // Write HTTP 200 message back to client before tunnel is actually made
    n = write(client_fd, CONNECT_INIT_RESPONSE, strlen(CONNECT_INIT_RESPONSE));
    if (n < 0) {
      // error("ERROR couldnt write to client");
      close(server_fd);
      handle_error(client_fd, pthread_self());
    }
  }

  client_r_fd = client_fd;
  server_r_fd = fileno(fdopen(server_fd, "r"));
  client_w_fd = client_fd;
  server_w_fd = fileno(fdopen(server_fd, "w"));
  timeout.tv_sec = TIMEOUT;
  timeout.tv_usec = 0;

  // Create tunnel to send messages directly between client and server
  while (1) {
    max_fd = client_r_fd >= server_r_fd ? client_r_fd : server_r_fd;

    FD_ZERO(&fdset);
    FD_SET(client_r_fd, &fdset);
    FD_SET(server_r_fd, &fdset);
    n = select(max_fd + 1, &fdset, (fd_set *)0, (fd_set *)0, &timeout);
    if (n <= 0) {
      continue;
      close(server_r_fd);
      close(server_w_fd);
      close(client_r_fd);
      close(client_w_fd);
      handle_error(client_fd, pthread_self());
      return;
    } else if (FD_ISSET(client_r_fd, &fdset)) {
      // Client has something to say
      n = read(client_r_fd, buf, sizeof(buf));

      if (n <= 0) {
        break;
        printf("  error CONNECT: read from client\n");
        close(server_r_fd);
        close(server_w_fd);
        close(client_r_fd);
        close(client_w_fd);
        handle_error(client_fd, pthread_self());
        return;
      }

      n = write(server_w_fd, buf, n);

      if (n < 0) {
        printf("  error CONNECT: write from client to server\n");
        close(server_r_fd);
        close(server_w_fd);
        close(client_r_fd);
        close(client_w_fd);
        handle_error(client_fd, pthread_self());
        return;
      }

      continue;
    } else if (FD_ISSET(server_r_fd, &fdset)) {
      // Server has something to say
      n = read(server_r_fd, buf, sizeof(buf));

      if (n < 0) {
        printf("  error CONNECT: read from server\n");
        close(server_r_fd);
        close(server_w_fd);
        close(client_r_fd);
        close(client_w_fd);
        handle_error(client_fd, pthread_self());
        return;
      }

      if (n == 0) {
        break;
      }

      n = write(client_w_fd, buf, n);

      if (n < 0) {
        printf("  error CONNECT: write from server to client\n");
        close(server_r_fd);
        close(server_w_fd);
        close(client_r_fd);
        close(client_w_fd);
        handle_error(client_fd, pthread_self());
        return;
      }

      continue;
    }
  }

  // only closing server fds because client_fd is closed after this function
  // is called in proxy_fun
  close(server_r_fd);
  close(server_w_fd);
  close(server_fd);
  close(client_w_fd);
  close(client_r_fd);
  pthread_exit(NULL);
}

/* Thread function per node in cooperative cache */
void *node_fun(void *args) {
  struct node_params *ns = args;
  int fd = ns->fd;
  int idx = ns->idx;
  uint32_t *node_flags = ns->nodeflags;
  int *node_fds = ns->node_fds;
  Cache_T c = ns->c;
  int bytes;
  int tot_bytes;
  char *req_type, *buf, *uri, *res;
  printf("Starting thread for %d\n", fd);
  while (1) {
    int content_length = -1;
    buf = malloc(BUFSIZE);
    bytes = 0;
    tot_bytes = 0;
    bytes = read(fd, buf, 1024);
    printf("node_fun: init bytes: %d\n", bytes);
    if (bytes <= 0) {
      int mask = 1 << (31 - idx);
      *node_flags = *node_flags ^ mask;
      node_fds[idx] = 0;
      printf("Node failure detected for %d, closing thread\n", fd);
      close(fd);
      pthread_exit(NULL);
    }
    tot_bytes = bytes;
    while (bytes == 1024 || tot_bytes < content_length) {
      if (content_length < 0 && check_header(buf, "Content-Length: ") != NULL) {
        content_length = parse_int_from_header(buf, "Content-Length: ");
        content_length = content_length + (strstr(buf, "\r\n\r\n") + 4 - buf);
      }
      bytes = read(fd, buf + bytes, 1024);
      if (bytes <= 0) {
        int mask = 1 << (31 - idx);
        *node_flags = *node_flags ^ mask;
        node_fds[idx] = 0;
        printf("Node failure detected for %d, closing thread\n", fd);
        close(fd);
        pthread_exit(NULL);
      }
      tot_bytes += bytes;
    }
    req_type = get_read_type(buf);
    if (strcmp(req_type, "GET") == 0) {
      uri = make_uri(split_request(buf));
      pthread_mutex_lock(&lock);
      res = cache_get(c, uri);
      pthread_mutex_unlock(&lock);
      if (res == NULL) {
        // response not found in cache --> request from server, cache,
        // send
        res = get_server_response(fd, buf);
        if (check_header(res, "max-age=") != NULL) {
          pthread_mutex_lock(&lock);
          cache_put(c, uri, res, parse_int_from_header(res, "max-age="));
          pthread_mutex_unlock(&lock);
        } else {
          pthread_mutex_lock(&lock);
          cache_put(c, uri, res, 3600);
          pthread_mutex_unlock(&lock);
        }
        printf("Fetched %s from server\n", uri);
        write_client_response(fd, res);

      } else {
        // response found in cache --> send back to client w/ new header
        printf("Fetched %s from cache\n", uri);
        res = add_header(res, cache_ttl(c, uri));
        write_client_response(fd, res);
        free(res);
      }
      printf("GET response sent for socket %d\n", fd);
      free(buf);
    } else if (strcmp(req_type, "RES") == 0) {
      pthread_mutex_lock(&read_locks[idx]);
      resbufs[idx] = buf;
      pthread_cond_signal(&read_conds[idx]);
      pthread_mutex_unlock(&read_locks[idx]);
    }
  }
}

/* Joins coop cache and sets state by sending request to node already in */
void join_coop_cache(char *local_hostname, int local_port, char *node_hostname,
                     char *node_port, int *fds, int localfd, uint32_t *flags,
                     uint32_t *mask, struct NodeData *node_conn_info,
                     Cache_T c) {
  struct sockaddr_in nodeaddr;
  struct hostent *server;
  struct Bootstrap boot_msg;
  struct Bootstrap temp_msg;
  int bytes = 0;
  struct Join join_msg;
  pthread_t *n;
  struct node_params *ns;
  strncpy(join_msg.join_str, "JOIN-", 5);
  strncpy(join_msg.local_hostname, local_hostname, strlen(local_hostname));
  join_msg.local_port = (unsigned short)local_port;
  strcpy(join_msg.end_str, "\r\n\r\n");

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    error("ERROR opening socket");

  server = gethostbyname(node_hostname);
  if (server == NULL) {
    fprintf(stderr, "Invalid hostname for cooperative cache\n");
    exit(EXIT_FAILURE);
  }

  bzero((char *)&nodeaddr, sizeof(nodeaddr));
  nodeaddr.sin_family = AF_INET;
  memcpy((char *)server->h_addr, (char *)&nodeaddr.sin_addr.s_addr,
         server->h_length);
  nodeaddr.sin_port = htons(atoi(node_port));

  if (connect(sockfd, (struct sockaddr *)&nodeaddr, sizeof(nodeaddr)) < 0) {
    error("ERROR connecting");
  }

  if (write(sockfd, &join_msg, sizeof(struct Join)) < 0)
    error("ERROR writing JOIN message");

  printf("Sent Join to %s:%s\n", node_hostname, node_port);

  bytes = read(sockfd, &boot_msg, sizeof(struct Bootstrap));
  while (bytes > 0) {
    bytes = read(sockfd, (&boot_msg) + bytes, sizeof(struct Bootstrap) - bytes);
  }
  *flags = boot_msg.flag;
  *mask = boot_msg.mask;

  uint32_t loc = 1;
  uint32_t nodes_visited = 0;
  uint32_t shifts = 0;
  uint32_t popcount = __builtin_popcount(*flags);

  while (popcount > nodes_visited) {
    if (*flags & loc) {
      if (loc == *mask) {
        // local node, populate info in node_conn_info and fds
        fds[31 - shifts] = localfd;
        node_conn_info[31 - shifts].port = (unsigned short)local_port;
        strncpy(node_conn_info[31 - shifts].hostname, local_hostname,
                strlen(local_hostname));
      } else if (loc == boot_msg.sender_mask) {
        fds[31 - shifts] = sockfd;
        node_conn_info[31 - shifts].port = boot_msg.nodes[31 - shifts].port;
        strncpy(node_conn_info[31 - shifts].hostname,
                boot_msg.nodes[31 - shifts].hostname,
                strlen(boot_msg.nodes[31 - shifts].hostname));
        n = malloc(sizeof(pthread_t));
        ns = malloc(sizeof(struct proxy_params));
        ns->fd = sockfd;
        ns->idx = 31 - shifts;
        ns->c = c;
        ns->nodeflags = flags;
        ns->node_fds = fds;
        pthread_create(n, NULL, node_fun, ns);
      } else {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        char *temp_host = boot_msg.nodes[31 - shifts].hostname;
        unsigned short temp_port = boot_msg.nodes[31 - shifts].port;
        struct sockaddr_in temp_sock;
        struct hostent *temp_server = gethostbyname(temp_host);
        if (server == NULL) {
          fprintf(stderr, "Invalid hostname for cooperative cache\n");
          exit(EXIT_FAILURE);
        }

        bzero((char *)&temp_sock, sizeof(temp_sock));
        temp_sock.sin_family = AF_INET;
        memcpy((char *)temp_server->h_addr, (char *)&temp_sock.sin_addr.s_addr,
               temp_server->h_length);
        temp_sock.sin_port = htons(temp_port);

        if (connect(fd, (struct sockaddr *)&temp_sock, sizeof(temp_sock)) < 0) {
          *flags = *flags ^ loc;
          printf("Failed connecting to node with flag %d\n", loc);
        } else {
          if (write(fd, &join_msg, sizeof(struct Join)) < 0)
            error("ERROR writing JOIN message");

          printf("Sent Join to %s:%d\n", temp_host, temp_port);

          bytes = read(fd, &temp_msg, sizeof(struct Bootstrap));
          while (bytes > 0) {
            bytes =
                read(fd, (&temp_msg) + bytes, sizeof(struct Bootstrap) - bytes);
          }
          assert(temp_msg.flag == boot_msg.flag);
          fds[31 - shifts] = fd;
          node_conn_info[31 - shifts].port = temp_port;
          strncpy(node_conn_info[31 - shifts].hostname, temp_host,
                  strlen(temp_host));
          n = malloc(sizeof(pthread_t));
          ns = malloc(sizeof(struct proxy_params));
          ns->fd = fd;
          ns->idx = 31 - shifts;
          ns->c = c;
          ns->nodeflags = flags;
          ns->node_fds = fds;
          pthread_create(n, NULL, node_fun, ns);
        }
      }
      nodes_visited++;
    }
    loc = loc << 1;
    shifts++;
  }
  printf("Successfully joined!\n");
  return;
}

/* Handles addition of nodes to cooperative cache */
void handle_node_join(int connfd, uint32_t *node_fds, uint32_t *nodeflags,
                      uint32_t *mask, struct NodeData *node_conn_info,
                      char *req, Cache_T c) {

  printf("NODE connected\n");
  struct Bootstrap boot_msg;
  struct Join *join_msg = (void *)req;
  uint32_t nodes_visited, popcount;
  pthread_t *n;
  struct node_params *ns;
  /* find new nodes position */
  uint32_t loc, shifts;
  loc = 1;
  shifts = 0;
  while ((loc & *nodeflags) > 0) {
    shifts++;
    loc = loc << 1;
  }
  /* lock while fds and flags are being modified */
  pthread_mutex_lock(&fd_lock);
  /* insert new node into fd array */
  node_fds[31 - shifts] = connfd;
  node_conn_info[31 - shifts].port = join_msg->local_port;
  strncpy(node_conn_info[31 - shifts].hostname, join_msg->local_hostname,
          strlen(join_msg->local_hostname));
  *nodeflags = *nodeflags | loc;

  boot_msg.flag = *nodeflags;
  boot_msg.mask = loc;
  boot_msg.sender_mask = *mask;
  memcpy(&(boot_msg.nodes), node_conn_info, sizeof(struct NodeData) * 32);

  pthread_mutex_unlock(&fd_lock);

  printf("About to write bootstrap to node\n");
  write(connfd, (char *)&boot_msg, sizeof(struct Bootstrap));
  printf("Successfully wrote bootstrap to node\n");
  n = malloc(sizeof(pthread_t));
  ns = malloc(sizeof(struct proxy_params));
  ns->fd = connfd;
  ns->idx = 31 - shifts;
  ns->c = c;
  ns->nodeflags = nodeflags;
  ns->node_fds = node_fds;
  pthread_create(n, NULL, node_fun, ns);
}

/* Thread function for new connections to proxy */
void *proxy_fun(void *args) {
  struct proxy_params *ps = args;
  int connfd = ps->connfd;
  int *node_fds = ps->node_fds;
  int *nodeflags = ps->nodeflags;
  int *nodemask = ps->nodemask;
  struct NodeData *node_conn_info = ps->node_conn_info;
  char **cf_arr = NULL;
  int cf_size = 0;
  if (ps->cf != NULL) {
    printf("HERE!");
    cf_arr = ps->cf[0];
    cf_size = *(int *)ps->cf[1];
  }
  int dest_node = 1;
  int mask, shifts;
  struct sockaddr_in node;
  socklen_t node_size = sizeof(node);
  Cache_T c = ps->c;
  pthread_t *currthread = ps->t;
  char *req, *res, *uri;
  char *req_type;
  printf("(%d) === Starting thread\n", connfd);

  req = read_client_req(connfd);
  req_type = get_req_type(req); // either "CONNECT" or "GET"
  if (strcmp(req_type, "GET") == 0 || strcmp(req_type, "CONNECT") == 0) {
    if (cf_arr && (cf_size > 0)) {
      void **arr = split_request(req);
      char *host = arr[1];
      for (int i = 0; i < cf_size; i++) {
        if (strstr(host, cf_arr[i])) {
          int n = write(connfd, FORBIDDEN_RESPONSE, strlen(FORBIDDEN_RESPONSE));
          printf("In content filter, sending FORBIDDEN\n");
          handle_error(connfd, pthread_self());
        }
      }
    }
  }
  if (strcmp(req_type, "GET") == 0) {
    // Handle GET request
    handle_get_req(args, req);
  } else if (strcmp(req_type, "CONNECT") == 0) {
    // Handle CONNECT request
    handle_connect_req(connfd, req);
    close(connfd);
  } else if (strcmp(req_type, "JOIN") == 0) {
    // Handle JOIN request for Coop cache
    handle_node_join(connfd, node_fds, nodeflags, nodemask, node_conn_info, req,
                     c);
    pthread_exit(NULL);
  } else if (strcmp(req_type, "POST") == 0) {
    handle_error(connfd, pthread_self());
  } else {
    // Not CONNECT or GET request --> error
    handle_error(connfd, pthread_self());
  }
  free(req);
  free(ps);
  free(uri);
  printf("(%d) Closing thread for\n", connfd);
  close(connfd);
  pthread_exit(NULL);
}

void *ssl_proxy_fun(void *args) {
  struct proxy_params *ps = args;
  int connfd = ps->connfd;
  int *node_fds = ps->node_fds;
  int *nodeflags = ps->nodeflags;
  int *nodemask = ps->nodemask;
  struct NodeData *node_conn_info = ps->node_conn_info;
  int dest_node = 1;
  int mask, shifts;
  struct sockaddr_in node;
  socklen_t node_size = sizeof(node);
  Cache_T c = ps->c;
  pthread_t *currthread = ps->t;
  char *req, *res, *uri;
  char *req_type;
  int ssl_error_code;

  printf("(%d) === Starting thread\n", connfd);

  SSL_library_init();
  ERR_load_CRYPTO_strings();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  SSL_CTX *ssl_context = ssl_init_context(KEY_FILE, CERT_FILE);

  // Create buffered IO for client and SSL connection with that b_io
  BIO *ssl_client_b_io = BIO_new_socket(connfd, BIO_NOCLOSE);
  SSL *ssl_connection = SSL_new(ssl_context);
  SSL_set_bio(ssl_connection, ssl_client_b_io, ssl_client_b_io);
  // SSL_set_fd(ssl_connection, connfd);
  printf("(%d) Buffered IO and SSL connection created\n", connfd);

  req = read_client_req(connfd);
  req_type = get_req_type(req);
  char *host = split_request(req)[1];
  printf("(%d) ssl_proxy_fun: init_req_type: %s %s\n", connfd, req_type, host);

  if (strcmp(req_type, "CONNECT") == 0) {
    ssl_handle_connect_req(ssl_connection, connfd, req);
  } else if (strcmp(req_type, "GET") == 0) {
    handle_get_req(args, req);
  } else if (strcmp(req_type, "JOIN") == 0) {
    // Handle JOIN request for Coop cache
    handle_node_join(connfd, node_fds, nodeflags, nodemask, node_conn_info, req,
                     c);
  } else {
    printf("ERROR malformed request\n");
    handle_error(connfd, pthread_self());
  }
  return;
}

void handle_get_req(void *args, char *req) {
  struct proxy_params *ps = args;
  int connfd = ps->connfd;
  int *node_fds = ps->node_fds;
  int *nodeflags = ps->nodeflags;
  int *nodemask = ps->nodemask;
  struct NodeData *node_conn_info = ps->node_conn_info;
  int dest_node = 1;
  int mask, shifts;
  struct sockaddr_in node;
  socklen_t node_size = sizeof(node);
  Cache_T c = ps->c;
  pthread_t *currthread = ps->t;
  char *res, *uri;

  uri = make_uri(split_request(req));
  mask = 1;
  if (*nodeflags > 1) {
    dest_node = hash(uri) % __builtin_popcount(*nodeflags);
    dest_node = dest_node + 1;
    int nodes_visited = 0;
    shifts = 0;
    while (nodes_visited < dest_node) {
      if (mask & *nodeflags)
        nodes_visited++;
      if (nodes_visited != dest_node) {
        mask = mask << 1;
        shifts++;
      }
    }
  }
  if (*nodeflags > 1 && mask != *nodemask) {
    printf("Sending GET request to node %d\n", node_fds[31 - shifts]);
    write(node_fds[31 - shifts], req, (strstr(req, "\r\n\r\n") + 4) - req);
    pthread_mutex_lock(&read_locks[31 - shifts]);
    while (resbufs[31 - shifts] == NULL) {
      pthread_cond_wait(&read_conds[31 - shifts], &read_locks[31 - shifts]);
    }
    pthread_mutex_unlock(&read_locks[31 - shifts]);
    write_client_response(connfd, resbufs[31 - shifts]);
    printf("GET response received and sent\n");
    free(resbufs[31 - shifts]);
    resbufs[31 - shifts] = NULL;
    close(connfd);
  } else {
    pthread_mutex_lock(&lock);
    res = cache_get(c, uri);
    pthread_mutex_unlock(&lock);
    if (res == NULL) {
      // response not found in cache --> request from server, cache,
      // send
      res = get_server_response(connfd, req);
      if (check_header(res, "max-age=") != NULL) {
        pthread_mutex_lock(&lock);
        cache_put(c, uri, res, parse_int_from_header(res, "max-age="));
        pthread_mutex_unlock(&lock);
      } else {
        pthread_mutex_lock(&lock);
        cache_put(c, uri, res, 3600);
        pthread_mutex_unlock(&lock);
      }
      printf("Fetched %s from server\n", uri);
      write_client_response(connfd, res);

    } else {
      // response found in cache --> send back to client w/ new header
      printf("Fetched %s from cache\n", uri);
      res = add_header(res, cache_ttl(c, uri));
      write_client_response(connfd, res);
      free(res);
    }
    printf("GET response sent for socket %d\n", connfd);
  }
}

void **get_cf_from_path(char *cf_path) {
  FILE *cf_file = fopen(cf_path, "r");
  char **cf_arr;
  int arr_length = 0;
  int longest_url_length = 0;
  int temp_url_length = 0;

  while (!feof(cf_file)) {
    int c = fgetc(cf_file);
    temp_url_length++;
    if (c == '\n' || c == EOF) {
      if (temp_url_length > longest_url_length) {
        longest_url_length = temp_url_length;
      }
      arr_length++;
      temp_url_length = 0;
    }
  }

  rewind(cf_file);
  cf_arr = malloc(sizeof(char *) * arr_length);

  char *line = malloc(sizeof(char) * longest_url_length);
  int read;
  if (cf_file) {
    int line_num = 0;
    while ((read = getline(&line, &longest_url_length, cf_file)) != -1) {
      for (int i = 0; i < strlen(line); i++) {
        if (line[i] == '\n')
          line[i] = '\0';
      }
      cf_arr[line_num] = line;
      line = malloc(sizeof(char) * longest_url_length);
      line_num++;
    }
    fclose(cf_file);
  }
  void **ret_vals = malloc(sizeof(void *) * 2);
  int *len = malloc(sizeof(int));
  *len = arr_length;
  ret_vals[0] = (void *)cf_arr;
  ret_vals[1] = (void *)len;

  return ret_vals;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr,
            "usage: %s <ip> <port> [-multi <node hostname> "
            "<node port>] [-ssl] [-cf <cf_path>]\n",
            argv[0]);
    exit(EXIT_FAILURE);
  }
  /* Initial server socket creation */
  int listenfd;                  /* listening socket */
  struct sockaddr_in serveraddr; /* server's addr */
  int portno = atoi(argv[2]);
  int connfd;
  int optval;
  char *multi_hostname;
  char *multi_portno;
  char *cf_path;
  FILE *cf_file;
  void **cf = NULL;
  uint32_t *nodemask = malloc(sizeof(uint32_t));
  uint32_t *nodeflags =
      malloc(sizeof(uint32_t)); /* Global storing all node fds */
  int *node_fds = malloc(sizeof(int) * 32);
  struct NodeData *node_conn_info = malloc(sizeof(struct NodeData) * 32);
  bzero((char *)node_conn_info, sizeof(struct NodeData) * 32);
  bool use_ssl = false;
  bool use_multi = false;
  for (int i = 0; i < argc; i++) {
    if (strcmp(argv[i], "-ssl") == 0) {
      use_ssl = true;
    }
    if (strcmp(argv[i], "-multi") == 0) {
      if (i + 2 >= argc) {
        fprintf(stderr,
                "usage: %s <ip> <port> [-multi <node hostname> "
                "<node port>] [-ssl] [-cf <cf_path>]\n",
                argv[0]);
        exit(EXIT_FAILURE);
      }
      multi_hostname = argv[i + 1];
      multi_portno = argv[i + 2];
      use_multi = true;
    }
    if (strcmp(argv[i], "-cf") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr,
                "usage: %s <ip> <port> [-multi <node hostname> "
                "<node port>] [-ssl] [-cf <cf_path>]\n",
                argv[0]);
        exit(EXIT_FAILURE);
      }
      cf_path = argv[i + 1];
      cf = get_cf_from_path(cf_path);
      printf("cf_path: %s\n", cf_path);
      printf("cf_size: %d\n", *(int *)cf[1]);
    }
  }

  if (use_ssl) {
    printf("SSL ACTIVE\n");
  } else {
    printf("SSL NOT ACTIVE\n");
  }

  /* Initializing state */
  for (int i = 0; i < 32; i++) {
    node_fds[i] = 0;
    pthread_mutex_init(&read_locks[i], NULL);
    pthread_cond_init(&read_conds[i], NULL);
    resbufs[i] = NULL;
  }
  Cache_T c;
  pthread_t *p;

  /* initialize cooperative cache state */
  assert(nodeflags != NULL && node_fds != NULL);
  *nodeflags = 0;

  listenfd = socket(AF_INET, SOCK_STREAM, 0);
  if (listenfd < 0)
    error("ERROR opening socket");

  /* setsockopt: Handy debugging trick that lets
   * us rerun the server immediately after we kill it;
   * otherwise we have to wait about 20 secs.
   * Eliminates "ERROR on binding: Address already in use" error.
   */
  optval = 1;
  setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
             sizeof(int));

  /* build the server's internet address */
  bzero((char *)&serveraddr, sizeof(serveraddr));
  serveraddr.sin_family = AF_INET; /* we are using the Internet */
  serveraddr.sin_addr.s_addr =
      htonl(INADDR_ANY); /* accept reqs to any IP addr */
  serveraddr.sin_port = htons((unsigned short)portno); /* port to listen on */

  /* bind: associate the listening socket with a port */
  if (bind(listenfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
    error("ERROR on binding");

  /* listen: make it a listening socket ready to accept connection
   * requests */
  if (listen(listenfd, 5) < 0) /* allow 5 requests to queue up */
    error("ERROR on listen");

  c = initialize_cache(20);
  pthread_mutex_init(&lock, NULL);
  pthread_mutex_init(&fd_lock, NULL);

  if (!use_multi) {
    *nodeflags = 1;
    node_fds[31] = listenfd;
    *nodemask = 1;
    strcpy(node_conn_info[31].hostname, argv[1]);
    node_conn_info[31].port = (unsigned short)portno;
  } else {
    join_coop_cache(argv[1], portno, multi_hostname, multi_portno, node_fds,
                    listenfd, nodeflags, nodemask, node_conn_info, c);
  }
  while (1) {
    connfd = get_client_connfd(listenfd);

    if (connfd < 0) {
      printf("error from get_client_connfd\n");
      // Error raised when trying to connect to client socket
      continue;
    }

    char *buf = malloc(sizeof(char) * 11);
    p = malloc(sizeof(pthread_t));
    struct proxy_params *ps = malloc(sizeof(struct proxy_params));
    ps->c = c;
    ps->connfd = connfd;
    ps->t = p;
    ps->node_fds = node_fds;
    ps->nodeflags = nodeflags;
    ps->nodemask = nodemask;
    ps->node_conn_info = node_conn_info;
    ps->cf = cf;

    if (use_ssl) {
      pthread_create(p, NULL, ssl_proxy_fun, ps);
    } else {
      printf("HERE\n");
      pthread_create(p, NULL, proxy_fun, ps);
    }
  }
}

void ssl_handle_connect_req(SSL *ssl, int client_fd, char *req) {
  printf("ssl_handle_connect_req: begin\n");
  int client_r_fd, server_r_fd, client_w_fd, server_w_fd;
  struct timeval timeout;
  fd_set fdset;
  int max_fd;
  char *buf = malloc(sizeof(char) * BUFSIZE);
  assert(buf != NULL);

  int server_fd, n, optval;
  int *portno;
  uint32_t res_sz = 0;
  struct sockaddr_in serveraddr;
  struct hostent *server;
  char *hostname;

  void **arr = split_request(req);

  SSL *ssl_server_connection;
  SSL_CTX *ssl_server_context;
  BIO *ssl_server_b_io;

  ssl_server_context = ssl_init_context(NULL, CERT_FILE);

  /* socket: create the socket */
  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    handle_error(client_fd, pthread_self());
  }

  optval = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
             sizeof(int));

  /* gethostbyname: get the server's DNS entry */
  hostname = arr[1];
  server = gethostbyname(hostname);
  if (server == NULL) {
    // invalid_hostname(hostname);
    close(server_fd);
    close(client_fd);
    pthread_exit(NULL);
  }
  portno = arr[2];
  /* build the server's Internet address */
  bzero((char *)&serveraddr, sizeof(serveraddr));
  serveraddr.sin_family = AF_INET;
  bcopy((char *)server->h_addr, (char *)&serveraddr.sin_addr.s_addr,
        server->h_length);
  serveraddr.sin_port = htons(*portno);

  // Create SSL connection for server (no handshake yet)
  ssl_server_connection = SSL_new(ssl_server_context);
  ssl_server_b_io = BIO_new_socket(server_fd, BIO_NOCLOSE);
  SSL_set_bio(ssl_server_connection, ssl_server_b_io, ssl_server_b_io);

  /* connect: create a connection with the server */
  if (connect(server_fd, &serveraddr, sizeof(serveraddr)) < 0) {
    close(server_fd);
    handle_error(client_fd, pthread_self());
  } else {
    int ssl_error_code;
    // SSL_connect: SSL handshake with server
    if ((ssl_error_code = SSL_connect(ssl_server_connection)) <= 0) {
      printf("SSL_connect to server returns %d\n", ssl_error_code);
      ssl_print_error(ssl_server_connection, ssl_error_code);
      close(server_fd);
      handle_error(client_fd, pthread_self());
    }

    printf("(%d) SSL handshake done with server\n", client_fd);

    // Check server certificate
    int a = ssl_check_cert(ssl_server_connection);
    printf("(%d) ssl_check_cert returned: %d\n", client_fd, a);

    // Connection succesfully established with server
    // Write HTTP 200 message to client
    printf("(%d) About to send HTTP 200 OK to client\n", client_fd);
    n = write(client_fd, CONNECT_INIT_RESPONSE, strlen(CONNECT_INIT_RESPONSE));
    if (n < 0) {
      close(server_fd);
      handle_error(client_fd, pthread_self());
    }
    printf("HTTP 200 OK sent to client\n");
  }

  // SSL_accept() for SSL handshake with client
  int ssl_error_code;
  if ((ssl_error_code = SSL_accept(ssl)) <= 0) {
    printf("(%d) ssl_proxy_fun: ERROR SSL_accept returned %d\n", client_fd,
           ssl_error_code);
    ssl_print_error(ssl, ssl_error_code);
  }
  printf("(%d) SSL handshake done with client\n", client_fd);

  timeout.tv_sec = TIMEOUT;
  timeout.tv_usec = 0;

  printf("(%d) About to SSL_read from client\n", client_fd);
  bzero(buf, sizeof(buf));
  char *request = ssl_read_client_req(ssl, client_fd);
  char *res =
      ssl_get_server_response(ssl, ssl_server_connection, client_fd, request);
  ssl_write_client_response(ssl, client_fd, res);

  while (1) {
    max_fd = client_fd >= server_fd ? client_fd : server_fd;
    FD_ZERO(&fdset);
    FD_SET(client_fd, &fdset);
    FD_SET(server_fd, &fdset);
    n = select(max_fd + 1, &fdset, (fd_set *)0, (fd_set *)0, &timeout);
    if (n <= 0) {
      continue;
    } else if (FD_ISSET(client_fd, &fdset)) {
      // Client has something to say
      n = SSL_read(ssl, buf, sizeof(buf));
      if (n <= 0) {
        break;
      }

      n = SSL_write(ssl_server_connection, buf, n);

      if (n < 0) {
        printf("(%d) SSL CONNECT ERROR writing from client to server\n",
               client_fd);
        close(server_fd);
        handle_error(client_fd, pthread_self());
        return;
      }

      continue;
    } else if (FD_ISSET(server_fd, &fdset)) {
      // Server has something to say
      n = SSL_read(ssl_server_connection, buf, sizeof(buf));

      if (n < 0) {
        printf("(%d) SSL CONNECT ERROR reading from server\n", client_fd);
        close(server_fd);
        handle_error(client_fd, pthread_self());
        return;
      }

      if (n == 0) {
        break;
      }

      n = SSL_write(ssl, buf, n);

      if (n < 0) {
        printf("  SSL CONNECT ERROR write from server to client\n");
        close(server_fd);
        handle_error(client_fd, pthread_self());
        return;
      }

      continue;
    }
  }

  // only closing server fds because client_fd is closed after this function
  // is called in proxy_fun
}