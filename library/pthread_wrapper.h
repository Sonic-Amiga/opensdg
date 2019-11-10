#ifndef INTERNAL_PTHREAD_WRAPPER_H
#define INTERNAL_PTHREAD_WRAPPER_H

#ifdef _WIN32

/*
 * This is in no way full pthreads implementation for Windows.
 * This is a lightweight wrapper, only enough for our own purposes.
 */

/* Prevent conflict between Windowx.h and Winsock2.h */
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>

typedef CRITICAL_SECTION pthread_mutex_t;

static inline int pthread_mutex_init(CRITICAL_SECTION *m, void *attr)
{
    InitializeCriticalSection(m);
    return 0;
}

static inline int pthread_mutex_destroy(CRITICAL_SECTION *m)
{
    DeleteCriticalSection(m);
    return 0;
}

static inline int pthread_mutex_lock(CRITICAL_SECTION *m)
{
    EnterCriticalSection(m);
    return 0;
}

static inline int pthread_mutex_unlock(CRITICAL_SECTION *m)
{
    LeaveCriticalSection(m);
    return 0;
}

#else

#include <pthread.h>

#endif
#endif
