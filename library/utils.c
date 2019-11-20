#include <sodium.h>

#include "logging.h"
#include "mainloop.h"
#include "opensdg.h"
#include "utils.h"

#ifndef _WIN32

static inline void WSACleanup()
{
}

#endif

int osdg_init(void)
{
    int res;

    if (sodium_init() == -1)
    {
        LOG(ERRORS, "libsodium init failed");
        return -1;
    }

#ifdef _WIN32
    WSADATA wsData;

    res = WSAStartup(MAKEWORD(2, 2), &wsData);
    if (res)
    {
        char *str;

        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, res, LANG_USER_DEFAULT, (LPSTR)&str, 1, NULL);

        LOG(ERRORS, "Winsock 2.2 init failed: %s", str);
        LocalFree(str);

        return -1;
    }
#endif

    mainloop_events_init();

    res = mainloop_init();
    if (!res)
        return 0;

    mainloop_events_shutdown();
    WSACleanup();
    return -1;
}

void osdg_shutdown(void)
{
    mainloop_shutdown();
    mainloop_events_shutdown();
    WSACleanup();
}

void osdg_create_private_key(osdg_key_t key)
{
    randombytes(key, crypto_box_SECRETKEYBYTES);
}

void osdg_bin_to_hex(char *hex, size_t hex_size, const unsigned char *bin, size_t bin_size)
{
    sodium_bin2hex(hex, hex_size, bin, bin_size);
}

int osdg_hex_to_bin(unsigned char *bin, size_t buffer_size, const unsigned char *hex, size_t hex_size,
                    const char *ignore, size_t *bin_size, const char **end_ptr)
{
    return sodium_hex2bin(bin, buffer_size, hex, hex_size, ignore, bin_size, end_ptr);
}

void queue_put(struct queue *q, struct queue_element *e)
{
    pthread_mutex_lock(&q->lock);

    e->next = NULL;
    q->tail->next = e;
    q->tail = e;

    pthread_mutex_unlock(&q->lock);
}

void *queue_get(struct queue *q)
{
    struct queue_element *e;

    pthread_mutex_lock(&q->lock);

    e = q->head;
    if (e)
        q->head = e->next;
    if (q->tail == e)
        q->tail = (struct queue_element *)&q->head;

    pthread_mutex_unlock(&q->lock);

    return e;
}
