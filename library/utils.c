#include <sodium.h>

#include "logging.h"
#include "mainloop.h"
#include "opensdg.h"
#include "utils.h"
#include "version.h"

#ifndef _WIN32

static inline void WSACleanup()
{
}

#endif

osdg_result_t osdg_init(void)
{
    int res;

    if (sodium_init() == -1)
    {
        LOG(ERRORS, "libsodium init failed");
        return osdg_crypto_core_error;
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

        return osdg_socket_error;
    }
#endif

    mainloop_events_init();

    res = mainloop_init();
    if (!res)
        return osdg_no_error;

    mainloop_events_shutdown();
    WSACleanup();
    return osdg_system_error;
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

void osdg_calc_public_key(osdg_key_t pubKey, const osdg_key_t secret)
{
    crypto_scalarmult_base(pubKey, secret);
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
    queue_put_nolock(q, e);
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

const char *osdg_get_result_str(osdg_result_t res)
{
    switch (res)
    {
    case osdg_no_error:
        return "No error";
    case osdg_socket_error:
        return "Socket I/O error";
    case osdg_crypto_core_error:
        return "Libsodium internal error";
    case osdg_decryption_error:
        return "Libsodium decryption error";
    case osdg_protocol_error:
        return "Unrecoverable protocol error";
    case osdg_buffer_exceeded:
        return "Buffer overrun";
    case osdg_invalid_parameters:
        return "Invalid function call parameters";
    case osdg_connection_failed:
        return "Failed to connect to host";
    case osdg_memory_error:
        return "Memory allocation error";
    case osdg_connection_refused:
        return "Connection refused by peer";
    case osdg_too_many_connections:
        return "Too many connections";
    case osdg_connection_closed:
        return "Connection closed by peer";
    case osdg_wrong_state:
        return "Connection is in wrong state";
    case osdg_system_error:
        return "General OS error";
    case osdg_server_error:
        return "Internal server error";
    case osdg_peer_timeout:
        return "Peer connection timeout";
    default:
        return "Unknon result code";
    }
}

void osdg_get_version(struct osdg_version* ver)
{
    ver->major = OSDG_MAJOR;
    ver->minor = OSDG_MINOR;
    ver->patch = OSDG_PATCH;
}
