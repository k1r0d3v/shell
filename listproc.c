#include "listproc.h"

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define PLIST_SIZE 4096

typedef struct plist_t 
{
    void *data[PLIST_SIZE];
    size_t count;
} plist_t;

int plist_create(plist_t **l)
{
    *l = malloc(sizeof(plist_t));
    if (*l == NULL) {
        perror("malloc");
        return -1;
    }
    (*l)->count = 0;
    return 0;
}

int plist_delete(plist_t **l)
{
    int i;
    for (i = 0; i < (*l)->count; i++)
        free((*l)->data[i]);
    free(*l);
    *l = NULL;
    return 0;
}

size_t plist_size(plist_t *l) {
    return l->count;
}

void *plist_value_at(plist_t *l, size_t index) {
    if (index >= l->count)
        return NULL;
    return l->data[index];
}

void *plist_add(plist_t *l, void *value, size_t vsize)
{
    void *m;

    if (l->count >= PLIST_SIZE)
        return NULL;

    m = malloc(vsize);
    if (m == NULL) {
        perror("malloc");
        return NULL;
    }
    memcpy(m, value, vsize);
    l->data[l->count++] = m;
    return m;
}