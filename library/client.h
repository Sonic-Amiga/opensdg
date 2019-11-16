#ifndef _INTERNAL_CLIENT_H
#define _INTERNAL_CLIENT_H

#include <errno.h>
#include "pthread_wrapper.h"

#include "opensdg.h"
#include "protocol.h"
#include "protocol.pb-c.h"
#include "uthash.h"

struct osdg_buffer
{
  struct osdg_buffer *next;
};

enum connection_mode
{
    mode_none,
    mode_grid,
    mode_peer
};

struct _osdg_connection
{
  UT_hash_handle       hh;
  int                  uid;
  SOCKET               sock;
  unsigned int         errorKind;
  unsigned int         errorCode;
  enum connection_mode mode;
  osdg_state_cb_t      changeState;
  osdg_receive_cb_t    receiveData;
  unsigned char        serverPubkey[crypto_box_PUBLICKEYBYTES];     /* Server's public key */
  unsigned char        clientTempPubkey[crypto_box_PUBLICKEYBYTES]; /* Client's short term key pair */
  unsigned char        clientTempSecret[crypto_box_SECRETKEYBYTES];
  unsigned char        serverCookie[curvecp_COOKIEBYTES];
  unsigned char        beforenmData[crypto_box_BEFORENMBYTES];
  unsigned long long   nonce;
  unsigned char       *tunnelId;
  size_t               tunnelIdSize;
  char                 haveBuffers;
  size_t               bufferSize;
  struct osdg_buffer  *bufferQueue;
  pthread_mutex_t      bufferMutex;
  unsigned char       *receiveBuffer;
  unsigned int         bytesReceived;
  unsigned int         bytesLeft;
  unsigned int         discardFirstBytes;
};

/* Client's long term key pair, global */
extern unsigned char clientPubkey[crypto_box_PUBLICKEYBYTES];
extern unsigned char clientSecret[crypto_box_SECRETKEYBYTES];

int connection_allocate_buffers(struct _osdg_connection *conn);
void *client_get_buffer(struct _osdg_connection *conn);
void client_put_buffer(struct _osdg_connection *conn, void *buffer);

void connection_read_data(struct _osdg_connection *conn);
int connection_handle_data(struct _osdg_connection *conn, const unsigned char *data, unsigned int length);
void connection_shutdown(struct _osdg_connection *conn);

static inline void connection_set_status(struct _osdg_connection *conn, enum osdg_connection_state state)
{
  if (conn->changeState)
    conn->changeState(conn, state);
}

int peer_handle_remote_call_reply(PeerReply *reply);

#endif
