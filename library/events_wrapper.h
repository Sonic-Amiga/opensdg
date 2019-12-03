#ifndef INTERNAL_EVENTS_WRAPPER_H
#define INTERNAL_EVENTS_WRAPPER_H

#ifdef _WIN32

/* Prevent conflict between Windowx.h and Winsock2.h */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

typedef HANDLE event_t;

static inline void event_init(event_t *ev)
{
    *ev = CreateEvent(NULL, FALSE, FALSE, NULL);
}

static inline void event_destroy(event_t *ev)
{
    CloseHandle(*ev);
    *ev = NULL;
}

static inline void event_wait(event_t *ev)
{
    WaitForSingleObject(*ev, INFINITE);
}

static inline void event_post(event_t *ev)
{
    SetEvent(*ev);
}

#else

#include <semaphore.h>

typedef sem_t event_t;

void event_init(event_t *ev)
{
    sem_init(ev, 0, 0);
}

void event_destroy(event_t *ev)
{
    sem_destroy(ev);
}

void event_wait(event_t *ev)
{
    sem_wait(ev);
}

void event_post(event_t *ev)
{
    sem_post(ev);
}

#endif

#endif