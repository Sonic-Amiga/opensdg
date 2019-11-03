#ifndef _OPENSDG_H
#define _OPENSDG_H

#ifdef _WIN32
#include <WinSock2.h>
#else
#define SOCKET int
#endif

typedef unsigned char osdg_key_t[32];

typedef struct _osdg_client *osdg_client_t;

osdg_client_t osdg_client_create(const osdg_key_t private_key);
void osdg_client_destroy(osdg_client_t client);

int osdg_client_connect_to_socket(osdg_client_t client, SOCKET s);

enum osdg_error_kind
{
  osdg_no_error,
  osdg_socket_error,
  osdg_sodium_error
};

enum osdg_error_kind osdg_client_get_error_kind(osdg_client_t client);
int osdg_client_get_error_code(osdg_client_t client);

#endif