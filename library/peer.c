#include <sodium.h>

#include "client.h"
#include "protocol.h"
#include "logging.h"
#include "mainloop.h"
#include "opensdg.h"
#include "registry.h"
#include "socket.h"

int osdg_connect_to_remote(osdg_connection_t grid, osdg_connection_t peer, osdg_key_t peerId, const char *protocol)
{
  int ret = connection_allocate_buffers(peer);

  if (ret)
    return ret;

  peer->mode = mode_peer;
  memcpy(peer->serverPubkey, peerId, sizeof(osdg_key_t));

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

  strncpy(peer->protocol, protocol, sizeof(peer->protocol));

  peer->grid = grid;
  peer->req.code = REQUEST_CALL_REMOTE;

  mainloop_send_client_request(&peer->req);
  return 0;
}

static int pairing_handle_incoming_packet(struct _osdg_connection *conn,
                                          const unsigned char *data, unsigned int length)
{
    unsigned char msgType;

    /*
     * Grid messages come in protobuf format, prefixed by one byte, indicating
     * message type.
     */
    if (length == 0)
    {
        LOG(ERRORS, "Empty pairing packet received");
        return 0; /* Ignore this */
    }

    msgType = *data++;
    length--;

    /* TODO: Figure out how to reply to message type 3.
     * The body is binary, 0x60 bytes (3 * 32). Looks like some crypto magic. */
    DUMP(PROTOCOL, data, length, "Pairing message type %u", msgType);
    return 0;
}

int osdg_pair_remote(osdg_connection_t grid, osdg_connection_t peer, const char *otp)
{
    size_t len = strlen(otp);
    int ret;

    if (len < SDG_MIN_OTP_LENGTH)
    {
        peer->errorKind = osdg_invalid_parameters;
        return -1;
    }

    if (len >= SDG_MAX_OTP_BYTES)
        len = SDG_MAX_OTP_BYTES - 1;

    /* It is a protocol property to remove last 3 characters of the OTP. It's unknown, why... */
    len -= 3;

    /* Reuse protocol for OTP */
    memcpy(peer->protocol, otp, len);
    peer->protocol[len] = 0;

    /* Don't return garbage from osdg_get_peer_id() */
    memset(peer->serverPubkey, 0, sizeof(peer->serverPubkey));

    ret = connection_allocate_buffers(peer);
    if (ret)
        return ret;

    peer->discardFirstBytes = 0;
    peer->receiveData = pairing_handle_incoming_packet;
    peer->mode = mode_peer;
    peer->grid = grid;
    peer->req.code = REQUEST_PAIR_REMOTE;

    mainloop_send_client_request(&peer->req);
    return 0;
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

int peer_call_remote(struct _osdg_connection *peer)
{
    ConnectToPeer request = CONNECT_TO_PEER__INIT;
    char peerIdStr[crypto_box_PUBLICKEYBYTES * 2 + 1];

    sodium_bin2hex(peerIdStr, sizeof(peerIdStr), peer->serverPubkey, sizeof(peer->serverPubkey));

    registry_add_connection(peer);

    LOG(PROTOCOL, "Peer[%u] connecting to %s:%s", peer->uid, peerIdStr, peer->protocol);

    request.id       = peer->uid;
    request.peerid   = peerIdStr;
    request.protocol = peer->protocol;

    return sendMESG(peer->grid, MSG_CALL_REMOTE, &request);
}

int peer_pair_remote(struct _osdg_connection *peer)
{
    PairRemote request = PAIR_REMOTE__INIT;

    registry_add_connection(peer);
    LOG(PROTOCOL, "Peer[%u] remote pairing OTP %s", peer->uid, peer->protocol);

    request.id = peer->uid;
    request.otp = peer->protocol;

    return sendMESG(peer->grid, MSG_PAIR_REMOTE, &request);
}
