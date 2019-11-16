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

OSDG_API int osdg_init(const osdg_key_t private_key);

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

typedef int(*osdg_receive_cb_t)(osdg_connection_t conn, const unsigned char *data, int length);

OSDG_API int osdg_set_receive_data_callback(osdg_connection_t client, osdg_receive_cb_t f);

enum osdg_error_kind
{
  osdg_no_error,           /* Everything is OK */
  osdg_socket_error,       /* Socket I/O error */
  osdg_encryption_error,   /* Sodium encryption error; should never happen */
  osdg_decryption_error,   /* Sodium decryption error; likely corrupted data */
  osdg_protocol_error,     /* Some invalid data has been received */
  osdg_buffer_exceeded,    /* Buffer size is not enough for incoming data */
  osdg_invalid_parameters, /* Invalid parameters supplied to function call */
  osdg_connection_failed,  /* Unable to connect to any server */
  osdg_memory_error        /* Memory (e. g. buffers) allocation error */
};

OSDG_API enum osdg_error_kind osdg_get_error_kind(osdg_connection_t client);
OSDG_API int osdg_get_error_code(osdg_connection_t client);
OSDG_API const unsigned char *osdg_get_peer_id(osdg_connection_t conn);

OSDG_API int osdg_main(void);


#endif
