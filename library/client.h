#ifndef _INTERNAL_CLIENT_H
#define _INTERNAL_CLIENT_H

#include <errno.h>
#include "pthread_wrapper.h"

#include "opensdg.h"
#include "tunnel_protocol.h"
#include "control_protocol.pb-c.h"
#include "utils.h"

struct osdg_buffer
{
    struct queue_element qe;
};

enum request_code
{
    REQUEST_ADD,
    REQUEST_CLOSE,
    REQUEST_CALL_REMOTE,
    REQUEST_PAIR_REMOTE
};

struct client_req
{
    struct queue_element qe;
    enum request_code    code;
};

enum connection_mode
{
    mode_none,
    mode_grid,
    mode_peer,
    mode_pairing
};

struct _osdg_connection
{
  struct client_req          req;
  struct list_element        forwardReq;
  int                        uid;
  SOCKET                     sock;
  osdg_result_t              errorKind;
  unsigned int               errorCode;
  enum connection_mode       mode;
  enum osdg_connection_state state;
  osdg_state_cb_t            changeState;
  osdg_receive_cb_t          receiveData;
  unsigned char              serverPubkey[crypto_box_PUBLICKEYBYTES];     /* Server's public key */
  unsigned char              clientTempPubkey[crypto_box_PUBLICKEYBYTES]; /* Client's short term key pair */
  unsigned char              clientTempSecret[crypto_box_SECRETKEYBYTES];
  unsigned char              serverCookie[curvecp_COOKIEBYTES];
  unsigned char              beforenmData[crypto_box_BEFORENMBYTES];
  unsigned long long         nonce;
  unsigned char             *tunnelId;
  size_t                     tunnelIdSize;
  osdg_connection_t          grid;
  struct list                forwardList;
  char                       protocol[SDG_MAX_PROTOCOL_BYTES];
  unsigned char              pairingResult[32];
  char                       haveBuffers;
  size_t                     bufferSize;
  struct queue               bufferQueue;
  unsigned char             *receiveBuffer;
  unsigned int               bytesReceived;
  unsigned int               bytesLeft;
  unsigned int               discardFirstBytes;
};

/* Client's long term key pair, global */
extern unsigned char clientPubkey[crypto_box_PUBLICKEYBYTES];
extern unsigned char clientSecret[crypto_box_SECRETKEYBYTES];

int connection_allocate_buffers(struct _osdg_connection *conn);
void *client_get_buffer(struct _osdg_connection *conn);

static inline void client_put_buffer(struct _osdg_connection *client, void *ptr)
{
    queue_put(&client->bufferQueue, ptr);
}

void connection_read_data(struct _osdg_connection *conn);
int connection_handle_data(struct _osdg_connection *conn, const unsigned char *data, unsigned int length);
void connection_shutdown(struct _osdg_connection *conn);
void connection_terminate(struct _osdg_connection *conn, enum osdg_connection_state state);
int connection_set_result(struct _osdg_connection *conn, osdg_result_t result);

static inline int connection_in_use(struct _osdg_connection *conn)
{
    return conn->state == osdg_connecting || conn->state == osdg_connected;
}

static inline void connection_set_status(struct _osdg_connection *conn, enum osdg_connection_state state)
{
  conn->state = state;
  if (conn->changeState)
    conn->changeState(conn, state);
}

int peer_call_remote(struct _osdg_connection *peer);
int peer_pair_remote(struct _osdg_connection *peer);
int peer_handle_remote_call_reply(struct _osdg_connection *peer, PeerReply *reply);

static inline struct _osdg_connection *get_connection(struct list_element *forwardReq)
{
    return (struct _osdg_connection *)((char *)forwardReq - offsetof(struct _osdg_connection, forwardReq));
}

#endif
