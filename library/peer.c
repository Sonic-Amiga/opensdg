#include <sodium.h>

#include "client.h"
#include "logging.h"
#include "opensdg.h"
#include "peer.h"
#include "protocol.pb-c.h"

osdg_peer_t osdg_peer_create(osdg_client_t client)
{
  struct _osdg_peer *peer = malloc(sizeof(struct _osdg_peer));

  if (!peer)
    return NULL;

  peer->client = client;
  return peer;
}

void osdg_peer_destroy(osdg_peer_t peer)
{
  free(peer);
}

int osdg_peer_connect(osdg_peer_t peer, osdg_key_t peerId, const char *protocol)
{
  char peerIdStr[sizeof(osdg_key_t) * 2 + 1];
  ConnectToPeer request = CONNECT_TO_PEER__INIT;

  memcpy(peer->peerId, peerId, sizeof(osdg_key_t));
  sodium_bin2hex(peerIdStr, sizeof(peerIdStr), peerId, sizeof(osdg_key_t));

  LOG(PROTOCOL, "Connecting to %s:%s", peerIdStr, protocol);

  request.unknown  = 0;
  request.peerid   = peerIdStr;
  request.protocol = protocol;

  return sendMESG(peer->client, MSG_CONNECT_TO_PEER, &request);
}

