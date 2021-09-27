/* Hash.h - Implementation of hash table with chaining  *
 * To be used with cache as fast access for cache queue *
 * Alexander Williams                                   */

#ifndef HASH_INCLUDED
#define HASH_INCLUDED
#include <stdint.h>
#include "queue.h"
#define H Hash_T
typedef struct H *H;
#define N Node_T

extern H initialize_table(u_int32_t);
extern void free_table(H);
extern void pretty_print_table(H);

extern char *node_key(N);
extern N list_ptr(N);
extern u_int32_t curr_blocks(H);
extern u_int32_t hash_size(H);

/* search by key */
extern N hash_search(H, char *);
/* insert node with key and list_ptr */
extern H hash_insert(H, char *, N);
/* delete node given key */
extern H hash_remove(H, char *);

#undef H
#endif