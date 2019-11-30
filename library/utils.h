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

static inline void queue_put_nolock(struct queue *q, struct queue_element *e)
{
    e->next = NULL;
    q->tail->next = e;
    q->tail = e;
}

void queue_put(struct queue *q, struct queue_element *e);
void *queue_get(struct queue *q);

struct list_element
{
    struct list_element *next;
    struct list_element *prev;
};

struct list
{
    struct list_element *head;
    struct list_element *stop;
    struct list_element *tail;
};

static inline void list_init(struct list *l)
{
    l->head = (struct list_element *)&l->stop;
    l->stop = NULL;
    l->tail = (struct list_element *)&l->head;
}

static inline void list_add(struct list *l, struct list_element *e)
{
    e->prev = l->tail;
    e->next = l->tail->next;
    l->tail->next = e;
    l->tail = e;
}

static inline void list_remove(struct list_element *e)
{
    e->prev->next = e->next;
    e->next->prev = e->prev;
    e->next = NULL;
    e->prev = NULL;
}

static inline struct list_element *list_tail(struct list *l)
{
    return l->tail->prev ? l->tail : NULL;
}

#define MILLISECONDS_PER_SECOND 1000

#ifdef _WIN32

static unsigned long long timestamp(void)
{
    return GetTickCount64();
}

#else

#include <time.h>

static unsigned long long timestamp(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

#endif

#endif