#ifndef INTERNAL_UTILS_H
#define INTERNAL_UTILS_H

#include "pthread_wrapper.h"

struct queue_element
{
    struct queue_element *next;
};

struct queue
{
    struct queue_element *head;
    struct queue_element *tail;
    pthread_mutex_t       lock;
};

static inline void queue_init(struct queue *q)
{
    q->head = NULL;
    q->tail = (struct queue_element *)&q->head;
    pthread_mutex_init(&q->lock, NULL);
}

static inline void queue_destroy(struct queue *q)
{
    pthread_mutex_destroy(&q->lock);
}

void queue_put(struct queue *q, struct queue_element *e);
void *queue_get(struct queue *q);

#endif