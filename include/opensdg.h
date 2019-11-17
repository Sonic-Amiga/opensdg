#ifndef _OPENSDG_H
#define _OPENSDG_H

#ifdef _WIN32
#include <WinSock2.h>
#ifdef OPENSDG_BUILD
#define OSDG_API __declspec(dllexport)
#else
#define OSDG_API __declspec(dllimport)
#endif
#else
#define SOCKET int
#define OSDG_API
#endif

typedef unsigned char osdg_key_t[32];

OSDG_API void osdg_set_private_key(const osdg_key_t private_key);
OSDG_API void osdg_create_private_key(osdg_key_t key);

typedef struct _osdg_connection *osdg_connection_t;

struct osdg_endpoint
{
  const char *host;
  unsigned int port;
};

OSDG_API osdg_connection_t osdg_connection_create(void);
OSDG_API void osdg_connection_destroy(osdg_connection_t client);

OSDG_API int osdg_connect_to_grid(osdg_connection_t client, const struct osdg_endpoint *servers);
OSDG_API int osdg_connect_to_remote(osdg_connection_t grid, osdg_connection_t peer, osdg_key_t peerId, const char *protocol);

enum osdg_connection_state
{
  osdg_not_connected,
  osdg_connected,
  osdg_error
};

typedef void(*osdg_state_cb_t)(osdg_connection_t conn, enum osdg_connection_state state);
typedef int(*osdg_receive_cb_t)(osdg_connection_t conn, const unsigned char *data, unsigned int length);

OSDG_API int osdg_set_state_change_callback(osdg_connection_t client, osdg_state_cb_t f);
OSDG_API int osdg_set_receive_data_callback(osdg_connection_t client, osdg_receive_cb_t f);

enum osdg_error_kind
{
  osdg_no_error,            /* Everything is OK */
  osdg_socket_error,        /* Socket I/O error */
  osdg_encryption_error,    /* Sodium encryption error; should never happen */
  osdg_decryption_error,    /* Sodium decryption error; likely corrupted data */
  osdg_protocol_error,      /* Some invalid data has been received */
  osdg_buffer_exceeded,     /* Buffer size is not enough for incoming data */
  osdg_invalid_parameters,  /* Invalid parameters supplied to function call */
  osdg_connection_failed,   /* Unable to connect to any server */
  osdg_memory_error,        /* Memory (e. g. buffers) allocation error */
  osdg_connection_refused,  /* Connection refused by peer */
  osdg_too_many_connections /* Connection count exceeds main loop capability */
};

OSDG_API enum osdg_error_kind osdg_get_error_kind(osdg_connection_t client);
OSDG_API int osdg_get_error_code(osdg_connection_t client);
OSDG_API const unsigned char *osdg_get_peer_id(osdg_connection_t conn);

OSDG_API int osdg_init(void);
OSDG_API void osdg_shutdown(void);
OSDG_API int osdg_main(void);

/* Log masks */
#define OSDG_LOG_ERRORS     0x01 /* Errors */
#define OSDG_LOG_CONNECTION 0x02 /* Connection events */
#define OSDG_LOG_PROTOCOL   0x04 /* Protocol */
#define OSDG_LOG_PACKETS    0x08 /* Raw packets */

OSDG_API osdg_set_log_mask(unsigned int mask);

OSDG_API void osdg_bin_to_hex(char *hex, size_t hex_size, const unsigned char *bin, size_t bin_size);
OSDG_API int osdg_hex_to_bin(unsigned char *bin, size_t buffer_size, const unsigned char *hex, size_t hex_size,
                             const char *ignore, size_t *bin_size, const char **end_ptr);

#endif
