#include <sodium.h>

#include "client.h"
#include "control_protocol.h"
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

int pairing_handle_incoming_packet(struct _osdg_connection *conn,
                                          const unsigned char *data, unsigned int length)
{
    /*
     * Grid messages come in protobuf format, prefixed by one byte, indicating
     * message type.
     */
    if (length == 0)
    {
        LOG(ERRORS, "Empty pairing packet received");
        return 0; /* Ignore this */
    }

    if (data[0] == MSG_PAIRING_CHALLENGE)
    {
        struct PairingChallenge *challenge = (struct PairingChallenge *)data;
        struct packetMESG *mesg = get_MESG_packet(conn, sizeof(struct PairingResponse));
        struct mesg_payload *payload;
        struct PairingResponse *response;
        size_t l;
        unsigned char buf[96];
        unsigned char hash[crypto_hash_BYTES];
        unsigned char xor[32];
        unsigned char rnd[crypto_scalarmult_SCALARBYTES];
        unsigned char base[crypto_scalarmult_BYTES];
        unsigned char p1[crypto_scalarmult_BYTES];

        if (!mesg)
          return -1;

        payload = (struct mesg_payload *)(mesg->mesg_payload - crypto_box_BOXZEROBYTES);
        response = (struct PairingResponse *)payload->data.data;
        response->msgCode = MSG_PAIRING_RESPONSE;

        LOG(PROTOCOL, "Connection[%p] received MSG_PAIRING_CHALLENGE:", conn);
        DUMP(PROTOCOL, challenge->X, sizeof(challenge->X), "X    ");
        DUMP(PROTOCOL, challenge->nonce, sizeof(challenge->nonce), "nonce");
        DUMP(PROTOCOL, challenge->Y, sizeof(challenge->Y), "Y    ");

        l = strlen(conn->protocol);
        memcpy(buf, conn->protocol, l);
        memcpy(&buf[l], clientPubkey, crypto_box_PUBLICKEYBYTES);
        memcpy(&buf[l + crypto_box_PUBLICKEYBYTES], conn->serverPubkey, crypto_box_PUBLICKEYBYTES);
        crypto_hash(buf, buf, l + crypto_box_PUBLICKEYBYTES * 2);

        memcpy(&buf[crypto_hash_BYTES], challenge->nonce, sizeof(challenge->nonce));
        crypto_hash(hash, buf, sizeof(buf));

        crypto_stream_xor(xor, challenge->Y, sizeof(challenge->Y), challenge->nonce, hash);
        crypto_scalarmult_base(base, conn->beforenmData);
        crypto_scalarmult(p1, xor, base);
        randombytes(rnd, sizeof(rnd));
        crypto_scalarmult(response->X, rnd, p1);

        /* This is used in both hashing rounds below, avoid copying */
        crypto_scalarmult(&buf[crypto_hash_BYTES], rnd, challenge->X);

        crypto_hash(buf, challenge->X, sizeof(challenge->X));
        crypto_hash(hash, buf, sizeof(buf));
        memcpy(response->Y, hash, sizeof(response->Y));

        crypto_hash(buf, response->X, sizeof(response->X));
        crypto_hash(hash, buf, sizeof(buf));
        memcpy(conn->pairingResult, hash, sizeof(conn->pairingResult));

        DUMP(PROTOCOL, hash, sizeof(conn->pairingResult), "Expected result");

        return send_MESG_packet(conn, mesg);
    }
    else if (data[0] == MSG_PAIRING_RESULT)
    {
        struct PairingResult *result = (struct PairingResult *)data;

        if (memcmp(result->result, conn->pairingResult, sizeof(result->result)))
        {
            DUMP(ERRORS, result->result, sizeof(result->result), "Received incorrect reply");
            return 0; /* Ignore for now, the remote hangs up anyways */
        }

        LOG(PROTOCOL, "MSG_PAIRING_RESULT successful");
        return 0;
    }

    /* TODO: Figure out how to reply to message type 3.
     * The body is binary, 0x60 bytes (3 * 32). Looks like some crypto magic. */
    DUMP(PROTOCOL, data, length, "Unknown pairing message type %u", data[0]);
    return 0;
}

int osdg_pair_remote(osdg_connection_t grid, osdg_connection_t peer, const char *otp)
{
    size_t len = strlen(otp);
    int ret;

    if (len < SDG_MIN_OTP_LENGTH || len >= SDG_MAX_OTP_BYTES)
    {
        peer->errorKind = osdg_invalid_parameters;
        return -1;
    }

    memcpy(peer->protocol, otp, len + 1);

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
    char otpServerPart[SDG_MAX_OTP_BYTES];
    size_t len = strlen(peer->protocol) - 3;

    /* We never send the whole OTP to the server, i guess for security.
     * We verify the complete thing during challenge-response verification */
    memcpy(otpServerPart, peer->protocol, len);
    otpServerPart[len] = 0;

    registry_add_connection(peer);
    LOG(PROTOCOL, "Peer[%u] remote pairing OTP %s", peer->uid, peer->protocol);

    request.id = peer->uid;
    request.otp = otpServerPart;

    return sendMESG(peer->grid, MSG_PAIR_REMOTE, &request);
}
