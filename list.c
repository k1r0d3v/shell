#include "list.h"
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>


struct list_node
{
    struct list_node *next;
};

int list_create(list_t **l)
{
    *l = (struct list_node*)malloc(sizeof(struct list_node));
    if (*l == NULL) 
        return -1;
    (*l)->next = NULL;
    return 0;
}

int list_delete(list_t **l) {
    if (l == NULL || *l == NULL)
        return -1;

    struct list_node *node = (*l)->next;
    while (node != NULL) {
        struct list_node *tmp = node->next;
        free(node);
        node = tmp;
    }

    free(*l);
    *l = NULL;

    return 0;
}

void *list_node_value(struct list_node *node)
{
    if (node == NULL)
        return NULL;

    return (void*)(node + 1);
}

struct list_node *list_next(struct list_node *node) {
    if (node == NULL)
        return NULL;
    return node->next;
}

struct list_node *list_insert_after(struct list_node *node, void *value, size_t vsize)
{
    struct list_node *next = node->next;

    struct list_node *newNode = (struct list_node*)malloc(sizeof(struct list_node) + vsize);
    if (newNode == NULL)
        return NULL;

    memcpy(newNode + 1, value, vsize);
    node->next = newNode;
    newNode->next = next;

    return newNode;
}

int list_remove(list_t *l, struct list_node *node)
{
    int i;
    struct list_node *tmp = l->next;
    struct list_node *last = l;

    for (i = 0; tmp != NULL; i++) 
    {
        if (tmp == node) {
            last->next = tmp->next;
            free(tmp);
            return 0;
        }

        last = tmp;
        tmp = tmp->next;
    }
    return -1;
}