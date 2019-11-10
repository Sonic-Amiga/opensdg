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

typedef struct
{
    HANDLE  handle;
    DWORD   id;
    void *(*start_routine) (void *);
    void   *arg;
} pthread_t;

/* We have to use trampoline because of WINAPI calling convention */
static DWORD WINAPI thread_trampoline(LPVOID arg)
{
    pthread_t *thread = arg;
    /* Double cast in order to avoid warning */
    return (DWORD)(__int64)thread->start_routine(thread->arg);
}

static inline int pthread_create(pthread_t *thread, const void *attr,
                                 void *(*start_routine) (void *), void *arg)
{
  thread->start_routine = start_routine;
  thread->arg = arg;
  thread->handle = CreateThread(NULL, 0, thread_trampoline, thread, 0, &thread->id);
  return thread->handle ? 0 : GetLastError();
}

#else

#include <pthread.h>

#endif
#endif
