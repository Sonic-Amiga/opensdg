#include <sodium.h>

#include "client.h"
#include "logging.h"
#include "opensdg.h"
#include "peer.h"

osdg_peer_t osdg_peer_create(osdg_client_t client)
{
  struct _osdg_peer *peer = malloc(sizeof(struct _osdg_peer));

  if (!peer)
    return NULL;

  peer->client = client;
  peer->id     = client_register_peer(client, peer);

  return peer;
}

void osdg_peer_destroy(osdg_peer_t peer)
{
  client_unregister_peer(peer->client, peer->id);
  free(peer);
}

int osdg_peer_connect(osdg_peer_t peer, osdg_key_t peerId, const char *protocol)
{
  char peerIdStr[sizeof(osdg_key_t) * 2 + 1];
  ConnectToPeer request = CONNECT_TO_PEER__INIT;

  memcpy(peer->peerId, peerId, sizeof(osdg_key_t));
  sodium_bin2hex(peerIdStr, sizeof(peerIdStr), peerId, sizeof(osdg_key_t));

  LOG(PROTOCOL, "Peer[%u] connecting to %s:%s", peer->id, peerIdStr, protocol);

  request.id       = peer->id;
  request.peerid   = peerIdStr;
  request.protocol = (char *)protocol;

  return sendMESG(peer->client, MSG_CONNECT_TO_PEER, &request);
}

const unsigned char *osdg_peer_get_id(osdg_peer_t peer)
{
  return peer->peerId;
}

int peer_handle_connect_reply(struct _osdg_peer *peer, PeerReply *reply)
{
  LOG(PROTOCOL, "Peer[%u] result %d\n", peer->id, reply->result);
  /* TODO: Figure out what to do next. We need something more in order
     to start receiving data */
  return 0;
}

