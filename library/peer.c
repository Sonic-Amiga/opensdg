#include <sodium.h>

#include "client.h"
#include "protocol.h"
#include "logging.h"
#include "opensdg.h"
#include "registry.h"

int osdg_connect_to_remote(osdg_client_t grid, osdg_client_t peer, osdg_key_t peerId, const char *protocol)
{
  char peerIdStr[sizeof(osdg_key_t) * 2 + 1];
  ConnectToPeer request = CONNECT_TO_PEER__INIT;
  int ret = connection_allocate_buffers(peer);

  if (ret)
    return ret;

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
    struct _osdg_client *peer;

    LOG(PROTOCOL, "Peer[%u] result %d\n", reply->id, reply->result);

    peer = registry_find_connection(reply->id);
    if (!peer)
    {
        LOG(ERRORS, "Received MSG_PEER_REPLY for nonexistent peer %u\n", reply->id);
        return 0; /* Ignore, this is not critical */
    }

    registry_remove_connection(peer);

    LOG(PROTOCOL, "Peer[%u] Forwarding ready at %s:%u", reply->id,
        reply->peer->server->host, reply->peer->server->port);
    DUMP(PROTOCOL, reply->peer->unknown.data, reply->peer->unknown.len,
           "Forwarding ticket is");

    /* TODO: Figure out what to do next. We need something more in order
       to start receiving data */
    return 0;
}
