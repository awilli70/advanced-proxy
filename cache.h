/* Cache.h - Implementation of insert/update/get cache  *
 * Uses double-linked list and hash table with chaining *
 * Alexander Williams                                   */

#ifndef CACHE_INCLUDED
#define CACHE_INCLUDED
#include <stdint.h>
#include "hash.h"
#include "queue.h"
#define C Cache_T
typedef struct C *C;
#define Q Queue_T
#define H Hash_T

extern C initialize_cache(u_int32_t);
extern void free_cache(C);

extern C cache_put(C, char *, char *, u_int32_t);
extern char *cache_get(C, char *);

#endif