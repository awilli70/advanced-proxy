/* Cache.h - Implementation of insert/update/get cache  *
 * Uses double-linked list and hash table with chaining *
 * Alexander Williams                                   */
#include "cache.h"
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define C Cache_T
#define H Hash_T
#define Q Queue_T
#define N Node_T

struct Q {
  struct N *head;
  struct N *tail;
};

struct N {
  char *key;
  char *data;
  uint32_t ttl;
  time_t created;
  struct N *prev;
  struct N *next;
  struct N *list_ptr;
};

struct H {
  uint32_t size;
  uint32_t curr_blocks;
  Queue_T *arr;
};

struct C {
  struct Q *objs;
  struct H *refs;
};

void update_node(N n, char *data, uint32_t ttl) {
  free(n->data);
  n->data = data;
  n->ttl = ttl;
  return;
}

C initialize_cache(uint32_t size) {
  C c = malloc(sizeof(struct Cache_T));
  c->objs = initialize_queue();
  c->refs = initialize_table(size);
  return c;
}

void free_cache(C c) {
  free_queue(c->objs);
  free_table(c->refs);
  free(c);
  return;
}

void clear_stales(C c) {
  time_t access;
  time(&access);
  Q q = c->objs;
  N n = q->head;
  char *stale_objs[c->refs->size];
  uint32_t i = 0;
  uint32_t elapsed;

  while (n != NULL) {
    elapsed = (uint32_t)difftime(access, n->created);
    if (elapsed > n->ttl && n->ttl != 0) {
      stale_objs[i] = n->key;
    } else {
      stale_objs[i] = NULL;
    }
    n = n->next;
    i++;
  }
  for (i = 0; i < c->refs->size; i++) {
    if (stale_objs[i] != NULL) {
      n = hash_search(c->refs, stale_objs[i])->list_ptr;
      hash_remove(c->refs, stale_objs[i]);
      delete_node(q, n);
    }
  }
}

C cache_put(C c, char *key, char *data, uint32_t ttl) {
  assert((c != NULL && key != NULL) && data != NULL);
  N n = hash_search(c->refs, key);
  if (n == NULL) {
    if (hash_size(c->refs) < (curr_blocks(c->refs) + 1)) {
      /* n doesn't exist, cache full */
      clear_stales(c);
      if (hash_size(c->refs) < (curr_blocks(c->refs) + 1)) {
        N del = tail(c->objs);
        c->refs = hash_remove(c->refs, node_key(del));
        pop(c->objs);
      }
      push(c->objs, key, data, ttl, NULL);
      hash_insert(c->refs, key, head(c->objs));
      assert(hash_size(c->refs) >= curr_blocks(c->refs));
      return c;
    } else {
      /* n doesn't exist, more room */
      push(c->objs, key, data, ttl, NULL);
      hash_insert(c->refs, key, head(c->objs));
      assert(hash_size(c->refs) >= curr_blocks(c->refs));
      return c;
    }
  } else {
    /* n exists */
    update_node(n->list_ptr, data, ttl);
    move_to_head(c->objs, n->list_ptr);
    return c;
  }
}

char *cache_get(C c, char *key) {
  N ref = hash_search(c->refs, key);
  time_t access;
  time(&access);
  if (ref != NULL) {
    N obj = list_ptr(ref);
    uint32_t elapsed = (uint32_t)difftime(access, obj->created);
    if (elapsed > obj->ttl) {
      delete_node(c->objs, obj);
      hash_remove(c->refs, key);
      return NULL;
    } else {
      return (data(obj));
    }
  } else {
    return NULL;
  }
}

uint32_t cache_ttl(C c, char *key) {
  N ref = hash_search(c->refs, key);
  assert(ref != NULL);
  time_t access;
  time(&access);
  if (ref != NULL) {
    N obj = list_ptr(ref);
    u_int32_t elapsed = (uint32_t)difftime(access, obj->created);
    return elapsed;
  }
}