#ifndef POINTER_LIST_H
#define POINTER_LIST_H

#include <stddef.h>

typedef struct plist_t plist_t;

int plist_create(plist_t **l);

int plist_delete(plist_t **l);

size_t plist_size(plist_t *l);

void *plist_value_at(plist_t *l, size_t index);

void *plist_add(plist_t *l, void *value, size_t vsize);

#endif