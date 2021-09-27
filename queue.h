/* Queue.h - Implementation of doubly linked list     *
 * To be used with cache as stale-checker and storage *
 * Alexander Williams                                 */ 

#ifndef QUEUE_INCLUDED
#define QUEUE_INCLUDED
#include <stdint.h>
#define Q Queue_T
typedef struct Q *Q;
#define N Node_T
typedef struct N *N;

extern Q initialize_queue();
extern void free_queue(Q);
extern void pretty_print_queue(Q);

extern N head(Q);
extern N tail(Q);
extern char *data(N);

/* Adds to head of queue, returns nothing */
extern Q push(Q, char *, char *, u_int32_t, N);
/* Removes from tail of queue, returns nothing */
extern Q pop(Q);
/* Move node to address */
extern Q move_to_head(Q, N);
/* Removes node from queue, fixes surrounding pointers */
extern Q delete_node(Q, N);
/* Traverse and find node by key */
extern N search_list(Q, char *);

#undef Q
#undef N
#endif
