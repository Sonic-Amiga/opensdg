#ifndef _INTERNAL_PEER_H
#define _INTERNAL_PEER_H

#include "protocol.pb-c.h"

struct _osdg_peer
{
  struct _osdg_client *client;
  unsigned int         id;     /* Internal ID of this connection */
  osdg_key_t           peerId; /* Our peer ID */
};

int peer_handle_remote_call_reply(struct _osdg_peer *peer, PeerReply *reply);

#endif
