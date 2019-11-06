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

typedef struct _osdg_client *osdg_client_t;

OSDG_API osdg_client_t osdg_client_create(const osdg_key_t private_key);
OSDG_API void osdg_client_destroy(osdg_client_t client);

OSDG_API int osdg_client_connect_to_socket(osdg_client_t client, SOCKET s);

enum osdg_error_kind
{
  osdg_no_error,         /* Everything is OK */
  osdg_socket_error,     /* Socket I/O error */
  osdg_encryption_error, /* Sodium encryption error; should never happen */
  osdg_decryption_error  /* Sodium decryption error; likely corrupted data */
};

OSDG_API enum osdg_error_kind osdg_client_get_error_kind(osdg_client_t client);
OSDG_API int osdg_client_get_error_code(osdg_client_t client);

#endif
