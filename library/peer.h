#ifndef _INTERNAL_PEER_H
#define _INTERNAL_PEER_H

struct _osdg_peer
{
  struct _osdg_client *client;
  osdg_key_t           peerId;
};

#endif
