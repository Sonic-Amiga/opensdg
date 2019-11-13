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

typedef struct _osdg_client *osdg_client_t;

struct osdg_endpoint
{
  const char *host;
  unsigned int port;
};

OSDG_API osdg_client_t osdg_connection_create(void);
OSDG_API void osdg_connection_destroy(osdg_client_t client);

OSDG_API int osdg_connect_to_grid(osdg_client_t client, const struct osdg_endpoint *servers);

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

OSDG_API enum osdg_error_kind osdg_get_error_kind(osdg_client_t client);
OSDG_API int osdg_get_error_code(osdg_client_t client);

typedef struct _osdg_peer *osdg_peer_t;

OSDG_API osdg_peer_t osdg_peer_create(osdg_client_t client);
OSDG_API void osdg_peer_destroy(osdg_peer_t peer);
OSDG_API int osdg_peer_connect(osdg_peer_t peer, osdg_key_t peerId, const char *protocol);
OSDG_API const unsigned char *osdg_peer_get_id(osdg_peer_t peer);

OSDG_API int osdg_main(void);


#endif
