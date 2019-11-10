#ifndef _INTERNAL_CLIENT_H
#define _INTERNAL_CLIENT_H

#include <errno.h>
#include "pthread_wrapper.h"

#include "opensdg.h"
#include "protocol.h"

struct osdg_buffer
{
  struct osdg_buffer *next;
};

struct _osdg_client
{
  SOCKET               sock;
  unsigned int         errorKind;
  unsigned int         errorCode;
  osdg_key_t           serverPubkey;                                /* Server's public key */
  unsigned char        clientPubkey[crypto_box_PUBLICKEYBYTES];     /* Client's long term key pair */
  const unsigned char *clientSecret;
  unsigned char        clientTempPubkey[crypto_box_PUBLICKEYBYTES]; /* Client's short term key pair */
  unsigned char        clientTempSecret[crypto_box_SECRETKEYBYTES];
  unsigned char        serverCookie[curvecp_COOKIEBYTES];
  unsigned char        beforenmData[crypto_box_BEFORENMBYTES];
  unsigned long long   nonce;
  size_t               bufferSize;
  struct osdg_buffer  *bufferQueue;
  pthread_mutex_t      bufferMutex;
  struct _osdg_peer  **peers;                                       /* Table of all peers */
  unsigned int         numPeers;                                    /* Number of entries in the table */
  pthread_mutex_t      peersMutex;
};

static inline void set_socket_error(struct _osdg_client *client)
{
  client->errorKind = osdg_socket_error;
#ifdef _WIN32
  client->errorCode = WSAGetLastError();
#else
  client->errorCode = errno;
#endif
}

static inline unsigned long long client_get_nonce(struct _osdg_client *client)
{
  unsigned long long nonce = client->nonce++;
  return SWAP_64(nonce); /* Our protocol wants bigendian data */
}

void *client_get_buffer(struct _osdg_client *client);
void client_put_buffer(struct _osdg_client *client, void *ptr);

unsigned int client_register_peer(struct _osdg_client *client, struct _osdg_peer *peer);
void client_unregister_peer(struct _osdg_client *client, unsigned int id);
struct _osdg_peer *client_find_peer(struct _osdg_client *client, unsigned int id);

#endif
