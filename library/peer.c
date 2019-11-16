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

    LOG(PROTOCOL, "Peer[%u] result %d\n", reply->id, reply->result);

    peer = registry_find_connection(reply->id);
    if (!peer)
    {
        LOG(ERRORS, "Received MSG_PEER_REPLY for nonexistent peer %u\n", reply->id);
        return 0; /* Ignore, this is not critical */
    }

    registry_remove_connection(peer);

    DUMP(PROTOCOL, reply->peer->tunnelid.data, reply->peer->tunnelid.len,
         "Peer[%u] Forwarding ready at %s:%u tunnel", reply->id,
         reply->peer->server->host, reply->peer->server->port);
 
    peer->tunnelIdSize = reply->peer->tunnelid.len;
    peer->tunnelId = malloc(peer->tunnelIdSize);
    if (!peer->tunnelId)
    {
        peer->errorKind = osdg_memory_error;
        return 0;
    }

    memcpy(peer->tunnelId, reply->peer->tunnelid.data, peer->tunnelIdSize);

    ret = connect_to_host(peer, reply->peer->server->host, reply->peer->server->port);
    if (ret == 0)
        peer->errorKind = osdg_connection_failed;

    return 0; /* We never abort grid connection */
}
