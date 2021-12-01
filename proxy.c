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

struct proxy_params {
  int connfd;
  uint32_t *nodeflags;
  uint32_t *nodemask;
  int *node_fds;
  Cache_T c;
  pthread_t *t;
  struct sockaddr_in *serveraddr;
  fd_set *active;
  int closed;
};

struct __attribute__((__packed__)) Bootstrap {
  uint32_t flag;
  uint32_t mask;
  uint32_t sender_mask;
  struct sockaddr_in nodes[32];
};

struct C {
  struct Q *objs;
  struct H *refs;
};

pthread_mutex_t lock;
pthread_mutex_t fd_lock;
pthread_mutex_t closed_lock;
int closed[32];

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

void join_coop_cache(char *node_hostname, char *node_port, int *fds,
                     int localfd, uint32_t *flags, uint32_t *mask,
                     fd_set *set) {
  struct sockaddr_in nodeaddr;
  struct hostent *server;
  struct Bootstrap boot_msg;
  int bytes = 0;
  char join_msg[10] = "JOIN-\r\n\r\n";

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

  if (write(sockfd, join_msg, 10) < 0)
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
  pthread_mutex_lock(&fd_lock);
  while (popcount > nodes_visited) {
    if (*flags & loc) {
      if (loc == *mask) {
        fds[31 - shifts] = localfd;
      } else if (loc == boot_msg.sender_mask) {
        fds[31 - shifts] = sockfd;
      } else {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in s = boot_msg.nodes[31 - shifts];
        if (connect(fd, (struct sockaddr *)&s, sizeof(s)) < 0) {
          *flags = *flags ^ loc;
          printf("Failed connecting to node with flag %d\n", loc);
          // TODO: send updates across to nodes after connecting
        } else {
          fds[31 - shifts] = fd;
          FD_SET(fd, set);
        }
      }
      nodes_visited++;
    }
    loc = loc << 1;
    shifts++;
  }
  FD_SET(sockfd, set);
  pthread_mutex_unlock(&fd_lock);
  printf("Successfully joined!\n");
  return;
}

void handle_node_join(int connfd, uint32_t *node_fds, uint32_t *nodeflags,
                      uint32_t *mask, struct sockaddr_in *serveraddr,
                      fd_set *active) {

  printf("NODE connected\n");
  struct Bootstrap boot_msg;
  struct sockaddr_in node;
  socklen_t node_size = sizeof(node);
  uint32_t nodes_visited, popcount;
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
  FD_SET(connfd, active);
  /* insert new node into fd array */
  node_fds[31 - shifts] = connfd;
  *nodeflags = *nodeflags | loc;

  boot_msg.flag = *nodeflags;
  boot_msg.mask = loc;
  boot_msg.sender_mask = *mask;
  /* populate array of sockaddr_in */
  loc = 1;
  shifts = 0;
  nodes_visited = 0;
  popcount = __builtin_popcount(*nodeflags);
  while (popcount > nodes_visited) {
    if ((loc & *nodeflags) > 0) {
      if (*mask == loc) {
        memcpy(&(boot_msg.nodes[31 - shifts]), serveraddr,
               sizeof(struct sockaddr_in));
        nodes_visited++;
      } else {
        if (getpeername(node_fds[31 - shifts], (struct sockaddr *)&node,
                        &node_size) < 0)
          error("ERROR copying peers");
      }
      memcpy(&(boot_msg.nodes[31 - shifts]), &node, sizeof(node));
      nodes_visited++;
    }
    loc = loc << 1;
    shifts++;
  }
  pthread_mutex_unlock(&fd_lock);
  write(connfd, (char *)&boot_msg, sizeof(struct Bootstrap));
  printf("Successfully wrote bootstrap to node\n");
}

void *proxy_fun(void *args) {
  struct proxy_params *ps = args;
  int connfd = ps->connfd;
  int *node_fds = ps->node_fds;
  int *nodeflags = ps->nodeflags;
  int *nodemask = ps->nodemask;
  fd_set *active = ps->active;
  int closed_idx = ps->closed;
  int dest_node = 1;
  int mask, shifts;
  struct sockaddr_in *serveraddr = ps->serveraddr;
  struct sockaddr_in node;
  socklen_t node_size = sizeof(node);
  Cache_T c = ps->c;
  pthread_t *currthread = ps->t;
  char *req, *res, *uri;
  char *req_type;
  printf("Starting thread for %d\n", connfd);

  req = read_client_req(connfd);
  // printf("%s", req);
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
      printf("closing fd\n");
      pthread_mutex_unlock(&closed_lock);
      pthread_mutex_lock(&closed_lock);
      closed[32 - shifts] = node_fds[32 - shifts];
      printf("Sending GET request to node %d\n", node_fds[31 - shifts]);
      write(node_fds[31 - shifts], req, (strstr(req, "\r\n\r\n") + 4) - req);
      printf("Sent\n");
      res = malloc(sizeof(char) * 4 * BUFSIZE);
      int n = read(node_fds[31 - shifts], res, 1024);
      int i = n;
      while (n == 1024) {
        printf("%d\n", n);
        n = read(node_fds[31 - shifts], res + i, 1024);
        i += n;
      }
      write_client_response(connfd, res);
      closed[32 - shifts] = -1;
      printf("GET response received and sent\n");
      close(connfd);
    } else {
      printf("GET request\n");
      pthread_mutex_unlock(&closed_lock);
      pthread_mutex_lock(&lock);
      res = cache_get(c, uri);
      pthread_mutex_unlock(&lock);
      if (res == NULL) {
        // response not found in cache --> request from server, cache, send
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
      if (connfd != closed[closed_idx])
        close(connfd);
    }
  } else if (strcmp(req_type, "CONNECT") == 0) {
    // Handle CONNECT request
    printf("CONNECT request\n");
    handle_connect_req(connfd, req);
    close(connfd);
  } else if (strcmp(req_type, "JOIN") == 0) {
    // Handle JOIN request for Coop cache
    handle_node_join(connfd, node_fds, nodeflags, nodemask, serveraddr, active);
    pthread_mutex_unlock(&closed_lock);
  } else {
    error("request not GET or CONNECT");
  }
  closed[closed_idx] = 0;
  free(req);
  free(ps);
  free(uri);
  printf("Closing thread for %d\n", connfd);
  pthread_exit(NULL);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <port> <node hostname> <node port>\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  /* Initial server socket creation */
  int listenfd;                  /* listening socket */
  struct sockaddr_in serveraddr; /* server's addr */
  int portno = atoi(argv[1]);
  int connfd;
  int optval;

  uint32_t *nodemask = malloc(sizeof(uint32_t));
  uint32_t *nodeflags =
      malloc(sizeof(uint32_t)); /* Global storing all node fds */
  int *node_fds = malloc(sizeof(int) * 32);
  for (int i = 0; i < 32; i++) {
    node_fds[i] = 0;
    closed[i] = -1;
  }
  Cache_T c;
  pthread_t *p;
  fd_set active_fd_set, read_fd_set;

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

  /* listen: make it a listening socket ready to accept connection requests */
  if (listen(listenfd, 5) < 0) /* allow 5 requests to queue up */
    error("ERROR on listen");

  FD_ZERO(&active_fd_set);
  FD_SET(listenfd, &active_fd_set);

  if (argc == 2) {
    *nodeflags = 1;
    node_fds[31] = listenfd;
    *nodemask = 1;
  } else {
    join_coop_cache(argv[2], argv[3], node_fds, listenfd, nodeflags, nodemask,
                    &active_fd_set);
  }
  c = initialize_cache(20);
  pthread_mutex_init(&lock, NULL);
  pthread_mutex_init(&fd_lock, NULL);
  pthread_mutex_init(&closed_lock, NULL);
  while (1) {
    pthread_mutex_lock(&fd_lock);
    read_fd_set = active_fd_set;
    pthread_mutex_unlock(&fd_lock);
    if (select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL) < 0) {
      error("select");
      exit(EXIT_FAILURE);
    }
    for (int i = 0; i < FD_SETSIZE; ++i) {
      if (FD_ISSET(i, &read_fd_set)) {
        if (i == listenfd) {
          connfd = get_client_connfd(listenfd);
          p = malloc(sizeof(pthread_t));
          struct proxy_params *ps = malloc(sizeof(struct proxy_params));
          ps->c = c;
          ps->connfd = connfd;
          ps->t = p;
          ps->node_fds = node_fds;
          ps->nodeflags = nodeflags;
          ps->nodemask = nodemask;
          ps->serveraddr = &serveraddr;
          ps->active = &active_fd_set;
          ps->closed = -1;

          pthread_create(p, NULL, proxy_fun, ps);
        } else {
          int create_thread = 1;
          int closed_index;
          connfd = i;
          if (pthread_mutex_trylock(&closed_lock) == 0) {
            pthread_mutex_unlock(&closed_lock);
            for (int j = 0; j < 32; j++) {
              if (connfd == closed[j]) {
                create_thread = 0;
              } else if (connfd == node_fds[j]) {
                closed[j] = connfd;
                closed_index = j;
              }
            }
            if (create_thread != 0) {
              p = malloc(sizeof(pthread_t));
              struct proxy_params *ps = malloc(sizeof(struct proxy_params));
              ps->c = c;
              ps->connfd = connfd;
              ps->t = p;
              ps->node_fds = node_fds;
              ps->nodeflags = nodeflags;
              ps->nodemask = nodemask;
              ps->serveraddr = &serveraddr;
              ps->active = &active_fd_set;
              ps->closed = closed_index;

              pthread_create(p, NULL, proxy_fun, ps);
            }
          }
        }
      }
    }
  }
}