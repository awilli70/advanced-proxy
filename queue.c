/* Queue.c - Implementation of doubly linked list *
 * To be used with cache as stale-checker         *
 * Alexander Williams                             */ 
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>
#include <string.h>
#include "queue.h"

#define Q Queue_T
#define N Node_T

struct N
{
    char *key;
    char *data;
    u_int32_t ttl;
    time_t created;
    struct N *prev;
    struct N *next;
    struct N *list_ptr;
};

struct Q
{
    struct N *head;
    struct N *tail;
};

Q initialize_queue() {
    Q q;
    q = malloc(sizeof(struct Queue_T));
    assert(q != NULL);
    q->head = NULL;
    q->tail = NULL;
    return q;
}
void free_queue(Q q) {
    while (q->tail != NULL) {
        q = pop(q);
    }
    assert (q->tail == NULL && q->head==NULL);
    free(q);
}

void pretty_print_queue(Q q) {
    struct N *n;
    if (q->head == NULL) {
        assert(q->tail == NULL);
        printf("Empty List\n");
    } else {
        n = q->head;
        while(n != NULL) {
            printf("%s-", n->data);
            n = n->next;
        }
        printf("|\n");
    }
    return;
}

struct N *head(Q q) {
    assert(q != NULL);
    return q->head;
}
struct N *tail(Q q) {
    assert(q != NULL);
    return q->tail;
}
char *data(N n) {
    assert(n != NULL);
    return n->data;
}

struct Q *push(Q q, char *key, char *data, u_int32_t ttl, N list_ptr) {
    assert(q != NULL && data != NULL && key != NULL);
    struct N *n;
    
    n = malloc(sizeof(struct Node_T));
    assert(n != NULL);
    n->key = key;
    n->data = data;
    n->ttl = ttl;
    n->created = time(&n->created);
    n->list_ptr = list_ptr;
    n->next = q->head;
    if (q->head != NULL) {
        q->head->prev = n;
    }
    n->prev = NULL;
    q->head = n;
    if (q->tail == NULL) {
        q->tail = n;
    }
    return q;
}

struct Q *pop(Q q) {
    assert(q != NULL && q->tail != NULL);
    struct N *n = q->tail;
    if (n == q->head) {
        q->head = NULL;
    }
    q->tail = n->prev;
    if (q->tail != NULL) {
        q->tail->next = NULL;
    }
    free(n->data);
    free(n->key);
    free(n);
    return q;
}

struct Q *move_to_head(Q q, N n) {
    if (n == q->head) {
        return q;
    } else if (n == q->tail) {
        q->tail = n->prev;
        q->tail->next = NULL;
        n->next = q->head;
        n->prev = NULL;
        q->head = n;
        if (q->tail->prev == NULL) {
            q->tail->prev = q->head;
        }
        return q;
    } else {
        n->prev->next = n->next;
        n->next->prev = n->prev;
        n->next = q->head;
        n->prev = NULL;
        q->head->prev = n;
        q->head = n;
        return q;
    }
}

struct Q *delete_node(Q q, N n) {
    if (n == q->head) {
        q->head = n->next;
        if (q->head != NULL) {
            q->head->prev = NULL;
        } else {
            q->tail = NULL;
        }
        free(n->data);
        free(n->key);
        free(n);
        return q;
    } else if (n == q->tail) {
        q->tail = n->prev;
        q->tail->next = NULL;
        free(n->data);
        free(n->key);
        free(n);
        return q;
    } else {
        n->prev->next = n->next;
        n->next->prev = n->prev;
        free(n->data);
        free(n->key);
        free(n);
        return q;
    }
}

struct N *search_list(Q q, char *key) {
    N n = q->head;
    while (n != NULL) {
        if (strcmp(n->key, key) == 0) {
            return n;
        }
        n = n->next;
    }
    return NULL;
}

#undef Q
#undef N
