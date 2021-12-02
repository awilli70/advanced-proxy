/*
 * HTTP proxy with cache
 * TODO: Error handling when node goes down
 */
#include "cache.h"
#include "client.h"
#include "error.h"
#include "parse.h"
#include "server.h"
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

#define TIMEOUT 3
#define BUFSIZE (10 * 1024 * 1024)

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
};

struct node_params {
  int fd;
  int idx;
  Cache_T c;
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
  const char *connection_established = "HTTP/1.1 200 OK\r\n\r\n";

  ///////////////////////////////
  int server_fd, n, optval;
  int *portno;
  uint32_t res_sz = 0;
  struct sockaddr_in serveraddr;
  struct hostent *server;
  char *hostname;
  void **arr = split_request(req);

  /* socket: create the socket */
  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0)
    error("ERROR opening socket");

  optval = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
             sizeof(int));

  /* gethostbyname: get the server's DNS entry */
  hostname = arr[1];
  server = gethostbyname(hostname);
  if (server == NULL) {
    invalid_hostname(hostname);
  }
  portno = arr[2];
  /* build the server's Internet address */
  bzero((char *)&serveraddr, sizeof(serveraddr));
  serveraddr.sin_family = AF_INET;
  bcopy((char *)server->h_addr, (char *)&serveraddr.sin_addr.s_addr,
        server->h_length);
  serveraddr.sin_port = htons(*portno);

  ///////////////////////////////

  /* connect: create a connection with the server */
  if (connect(server_fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) <
      0) {
    error("ERROR connecting");
  } else {
    // Connection succesfully established with server
    printf("proxy connected to server\n");
    // Write HTTP 200 message back to client before tunnel is actually made
    n = write(client_fd, connection_established,
              strlen(connection_established));
    if (n < 0) {
      error("ERROR couldnt write to client");
      // TODO: handle error
    }
    printf("proxy successful sent response to client after connection\n");
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
    if (n == 0) {
      // TODO: handle error
      return;
    } else if (FD_ISSET(client_r_fd, &fdset)) {
      // Client has something to say
      n = read(client_r_fd, buf, sizeof(buf));
      // TODO: handle error
      // TODO: handle disconnection
      if (n <= 0)
        break;
      n = write(server_w_fd, buf, n);

      // TODO: handle error
      if (n <= 0)
        break;
    } else if (FD_ISSET(server_r_fd, &fdset)) {
      // Server has something to say
      n = read(server_r_fd, buf, sizeof(buf));
      // TODO: handle error
      // TODO: handle disconnection
      if (n <= 0)
        break;
      n = write(client_w_fd, buf, n);

      // TODO: handle error
      if (n <= 0)
        break;
    }
  }

  // only closing server fds because client_fd is closed after this function
  // is called in proxy_fun
  close(server_r_fd);
  close(server_w_fd);
  close(server_fd);
}

/* Thread function per node in cooperative cache */
// TODO: Handle error when read fails
void *node_fun(void *args) {
  struct node_params *ns = args;
  int fd = ns->fd;
  int idx = ns->idx;
  Cache_T c = ns->c;
  uint32_t bytes;
  uint32_t tot_bytes;
  char *req_type, *buf, *uri, *res;
  printf("Starting thread for %d\n", fd);
  while (1) {
    buf = malloc(BUFSIZE);
    bytes = 0;
    tot_bytes = 0;
    bytes = read(fd, buf, 1024);
    tot_bytes = bytes;
    while (bytes == 1024) {
      bytes = read(fd, buf + bytes, 1024);
      tot_bytes += bytes;
    }

    req_type = get_read_type(buf);
    if (strcmp(req_type, "GET") == 0) {
      printf("GET request\n");
      uri = make_uri(split_request(buf));
      pthread_mutex_lock(&lock);
      res = cache_get(c, uri);
      pthread_mutex_unlock(&lock);
      if (res == NULL) {
        // response not found in cache --> request from server, cache,
        // send
        res = get_server_response(buf);
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

  write(connfd, (char *)&boot_msg, sizeof(struct Bootstrap));
  printf("Successfully wrote bootstrap to node\n");
  n = malloc(sizeof(pthread_t));
  ns = malloc(sizeof(struct proxy_params));
  ns->fd = connfd;
  ns->idx = 31 - shifts;
  ns->c = c;
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
  int dest_node = 1;
  int mask, shifts;
  struct sockaddr_in node;
  socklen_t node_size = sizeof(node);
  Cache_T c = ps->c;
  pthread_t *currthread = ps->t;
  char *req, *res, *uri;
  char *req_type;
  printf("Starting thread for %d\n", connfd);

  req = read_client_req(connfd);
  req_type = get_req_type(req); // either "CONNECT" or "GET"

  if (strcmp(req_type, "GET") == 0) {
    // Handle GET request
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
      printf("Sent\n");
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
      printf("GET request\n");
      pthread_mutex_lock(&lock);
      res = cache_get(c, uri);
      pthread_mutex_unlock(&lock);
      if (res == NULL) {
        // response not found in cache --> request from server, cache,
        // send
        res = get_server_response(req);
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
        // printf("%s", res);
        write_client_response(connfd, res);
        free(res);
      }
      printf("GET response sent for socket %d\n", connfd);
    }
  } else if (strcmp(req_type, "CONNECT") == 0) {
    // Handle CONNECT request
    printf("CONNECT request\n");
    handle_connect_req(connfd, req);
    close(connfd);
  } else if (strcmp(req_type, "JOIN") == 0) {
    // Handle JOIN request for Coop cache
    handle_node_join(connfd, node_fds, nodeflags, nodemask, node_conn_info, req,
                     c);
  } else {
    error("request not GET or CONNECT");
  }
  free(req);
  free(ps);
  free(uri);
  printf("Closing thread for %d\n", connfd);
  pthread_exit(NULL);
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s <ip> <port> <node hostname> <node port>\n",
            argv[0]);
    exit(EXIT_FAILURE);
  }
  /* Initial server socket creation */
  int listenfd;                  /* listening socket */
  struct sockaddr_in serveraddr; /* server's addr */
  int portno = atoi(argv[2]);
  int connfd;
  int optval;
  uint32_t *nodemask = malloc(sizeof(uint32_t));
  uint32_t *nodeflags =
      malloc(sizeof(uint32_t)); /* Global storing all node fds */
  int *node_fds = malloc(sizeof(int) * 32);
  struct NodeData *node_conn_info = malloc(sizeof(struct NodeData) * 32);
  bzero((char *)node_conn_info, sizeof(struct NodeData) * 32);

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

  if (argc == 3) {
    *nodeflags = 1;
    node_fds[31] = listenfd;
    *nodemask = 1;
    strcpy(node_conn_info[31].hostname, argv[1]);
    node_conn_info[31].port = (unsigned short)portno;
    printf("%s\n", node_conn_info[31].hostname);
  } else {
    join_coop_cache(argv[1], portno, argv[3], argv[4], node_fds, listenfd,
                    nodeflags, nodemask, node_conn_info, c);
  }
  while (1) {
    connfd = get_client_connfd(listenfd);
    p = malloc(sizeof(pthread_t));
    struct proxy_params *ps = malloc(sizeof(struct proxy_params));
    ps->c = c;
    ps->connfd = connfd;
    ps->t = p;
    ps->node_fds = node_fds;
    ps->nodeflags = nodeflags;
    ps->nodemask = nodemask;
    ps->node_conn_info = node_conn_info;

    pthread_create(p, NULL, proxy_fun, ps);
  }
}