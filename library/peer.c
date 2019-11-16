#include <sodium.h>

#include "client.h"
#include "protocol.h"
#include "logging.h"
#include "opensdg.h"
#include "registry.h"
#include "socket.h"

int osdg_connect_to_remote(osdg_connection_t grid, osdg_connection_t peer, osdg_key_t peerId, const char *protocol)
{
  char peerIdStr[sizeof(osdg_key_t) * 2 + 1];
  ConnectToPeer request = CONNECT_TO_PEER__INIT;
  int ret = connection_allocate_buffers(peer);

  if (ret)
    return ret;

  peer->mode = mode_peer;
  memcpy(peer->serverPubkey, peerId, sizeof(osdg_key_t));
  sodium_bin2hex(peerIdStr, sizeof(peerIdStr), peerId, sizeof(osdg_key_t));

  /*
   * DEVISmart thermostat has a quirk: very first packet is prefixed with
   * a garbage byte, which has to be skipped.
   * Apparently this is some buffering bug, which seems to have become a
   * part of the protocol spec ;) The original DEVISmart app implements
   * exactly this king of a logic in order to discard this byte: just remember
   * the fact that the connection is new.
   * Here we are generalizing this solution to "discard first N bytes", just
   * in case. If there are more susceptible peers, they need to be listed here
   * in order to prevent application writers from implementing the workaround
   * over and over again.
   */
  if (!strcmp(protocol, "dominion-1.0"))
      peer->discardFirstBytes = 1;
  else
      peer->discardFirstBytes = 0;

  registry_add_connection(peer);

  LOG(PROTOCOL, "Peer[%u] connecting to %s:%s", peer->uid, peerIdStr, protocol);

  request.id       = peer->uid;
  request.peerid   = peerIdStr;
  request.protocol = (char *)protocol;

  return sendMESG(grid, MSG_CALL_REMOTE, &request);
}

int peer_handle_remote_call_reply(PeerReply *reply)
{
    struct _osdg_connection *peer;
    int ret;

    peer = registry_find_connection(reply->id);
    if (!peer)
    {
        LOG(ERRORS, "Received MSG_PEER_REPLY for nonexistent peer %u\n", reply->id);
        return 0; /* Ignore, this is not critical */
    }

    registry_remove_connection(peer);

    if (reply->result || (!reply->peer))
    {
        LOG(CONNECTION, "Peer[%u] connection refused; code %d", reply->id, reply->result);
        peer->errorKind = osdg_connection_refused;
        connection_set_status(peer, osdg_error);
        return 0;
    }

    DUMP(PROTOCOL, reply->peer->tunnelid.data, reply->peer->tunnelid.len,
         "Peer[%u] Forwarding ready at %s:%u tunnel", reply->id,
         reply->peer->server->host, reply->peer->server->port);
 
    peer->tunnelIdSize = reply->peer->tunnelid.len;
    peer->tunnelId = malloc(peer->tunnelIdSize);
    if (!peer->tunnelId)
    {
        peer->errorKind = osdg_memory_error;
        connection_set_status(peer, osdg_error);
        return 0;
    }

    memcpy(peer->tunnelId, reply->peer->tunnelid.data, peer->tunnelIdSize);

    ret = connect_to_host(peer, reply->peer->server->host, reply->peer->server->port);
    if (ret == 0)
    {
        peer->errorKind = osdg_connection_failed;
        connection_set_status(peer, osdg_error);
    }

    return 0; /* We never abort grid connection */
}
