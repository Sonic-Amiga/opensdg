#ifndef _OPENSDG_H
#define _OPENSDG_H

#ifdef _WIN32
#include <WinSock2.h>
#ifndef OPENSDG_STATIC
#ifdef OPENSDG_BUILD
#define OSDG_API __declspec(dllexport)
#else
#define OSDG_API __declspec(dllimport)
#endif
#endif
#else
#define SOCKET int
#endif

#ifndef OSDG_API
#define OSDG_API
#endif

/* Some limits imposed by the protocol */
#define SDG_MAX_PROTOCOL_BYTES 40
#define SDG_MAX_OTP_BYTES      32
#define SDG_MIN_OTP_LENGTH      7

typedef unsigned char osdg_key_t[32];

/* API return codes */
typedef enum
{
    osdg_no_error,             /* Everything is OK */
    osdg_socket_error,         /* Socket I/O error */
    osdg_crypto_core_error,    /* Sodium internal error; should never happen */
    osdg_decryption_error,     /* Sodium decryption error; likely corrupted data */
    osdg_protocol_error,       /* Some invalid data has been received */
    osdg_buffer_exceeded,      /* Buffer size is not enough for incoming data */
    osdg_invalid_parameters,   /* Invalid parameters supplied to function call */
    osdg_connection_failed,    /* Unable to connect to any server */
    osdg_memory_error,         /* Memory (e. g. buffers) allocation error */
    osdg_connection_refused,   /* Connection refused by peer */
    osdg_too_many_connections, /* Connection count exceeds main loop capability */
    osdg_connection_closed,    /* Connection closed by peer */
    osdg_wrong_state,          /* A request is inappropriate for current connection state */
    osdg_system_error          /* General OS-specific error */
} osdg_result_t;

OSDG_API void osdg_set_private_key(const osdg_key_t private_key);
OSDG_API unsigned char *osdg_get_my_peer_id(void);
OSDG_API void osdg_create_private_key(osdg_key_t key);

typedef struct _osdg_connection *osdg_connection_t;

struct osdg_endpoint
{
  const char *host;
  unsigned int port;
};

OSDG_API osdg_connection_t osdg_connection_create(void);
OSDG_API void osdg_connection_destroy(osdg_connection_t client);

OSDG_API void osdg_set_user_data(osdg_connection_t conn, void *data);
OSDG_API void *osdg_get_user_data(osdg_connection_t conn);

OSDG_API osdg_result_t osdg_connect_to_danfoss(osdg_connection_t conn);
OSDG_API osdg_result_t osdg_connect_to_grid(osdg_connection_t client, const struct osdg_endpoint *servers, unsigned int num_servers);
OSDG_API osdg_result_t osdg_connect_to_remote(osdg_connection_t grid, osdg_connection_t peer, const osdg_key_t peerId, const char *protocol);
OSDG_API osdg_result_t osdg_pair_remote(osdg_connection_t grid, osdg_connection_t peer, const char *otp);
OSDG_API osdg_result_t osdg_connection_close(osdg_connection_t client);
OSDG_API osdg_result_t osdg_send_data(osdg_connection_t conn, const void *data, int size);

enum osdg_connection_state
{
  osdg_closed,
  osdg_connecting, /* State change callback is not called with this */
  osdg_connected,
  osdg_error,
  osdg_pairing_complete
};

OSDG_API void osdg_set_blocking_mode(osdg_connection_t conn, int blocking);
OSDG_API int osdg_get_blocking_mode(osdg_connection_t conn);
OSDG_API enum osdg_connection_state osdg_get_connection_state(osdg_connection_t conn);

typedef void(*osdg_state_cb_t)(osdg_connection_t conn, enum osdg_connection_state state);
typedef osdg_result_t (*osdg_receive_cb_t)(osdg_connection_t conn, const void *data, unsigned int length);

OSDG_API osdg_result_t osdg_set_state_change_callback(osdg_connection_t client, osdg_state_cb_t f);
OSDG_API osdg_result_t osdg_set_receive_data_callback(osdg_connection_t client, osdg_receive_cb_t f);

OSDG_API osdg_result_t osdg_get_last_result(osdg_connection_t client);
OSDG_API int osdg_get_last_errno(osdg_connection_t client);
OSDG_API const unsigned char *osdg_get_peer_id(osdg_connection_t conn);

OSDG_API osdg_result_t osdg_set_ping_interval(osdg_connection_t conn, unsigned int seconds);

OSDG_API osdg_result_t osdg_init(void);
OSDG_API void osdg_shutdown(void);

/* Log masks */
#define OSDG_LOG_ERRORS     0x01 /* Errors */
#define OSDG_LOG_CONNECTION 0x02 /* Connection events */
#define OSDG_LOG_PROTOCOL   0x04 /* Protocol */
#define OSDG_LOG_PACKETS    0x08 /* Raw packets */

OSDG_API void osdg_set_log_mask(unsigned int mask);

struct osdg_main_loop_callbacks
{
    void (*mainloop_start)(void);
    void (*mainloop_stop)(void);
};

OSDG_API void osdg_set_mainloop_callbacks(const struct osdg_main_loop_callbacks *cb);

OSDG_API void osdg_bin_to_hex(char *hex, size_t hex_size, const unsigned char *bin, size_t bin_size);
OSDG_API int osdg_hex_to_bin(unsigned char *bin, size_t buffer_size, const unsigned char *hex, size_t hex_size,
                             const char *ignore, size_t *bin_size, const char **end_ptr);

#endif
