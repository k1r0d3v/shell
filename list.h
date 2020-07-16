#ifndef LIST_H
#define LIST_H

#include <stddef.h>

struct list_node;
typedef struct list_node list_t;

int list_create(list_t **l);

int list_delete(list_t **l);

void *list_node_value(struct list_node *node);

struct list_node *list_next(struct list_node *node);

struct list_node *list_insert_after(struct list_node *node, void *value, size_t vsize);

int list_remove(list_t *l, struct list_node *node);

#endif
