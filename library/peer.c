#include <ctype.h>
#include <sodium.h>

#include "client.h"
#include "control_protocol.h"
#include "logging.h"
#include "mainloop.h"
#include "opensdg.h"
#include "socket.h"

static void registry_add_connection(struct _osdg_connection *peer)
{
    struct _osdg_connection *grid = peer->grid;
    struct list_element *req = list_tail(&grid->forwardList);

    peer->uid = req ? get_connection(req)->uid + 1 : 0;
    list_add(&peer->grid->forwardList, &peer->forwardReq);
}

static int peer_call_remote(struct _osdg_connection *peer)
{
    ConnectToPeer request = CONNECT_TO_PEER__INIT;
    char peerIdStr[crypto_box_PUBLICKEYBYTES * 2 + 1];
    osdg_result_t result;

    sodium_bin2hex(peerIdStr, sizeof(peerIdStr), peer->serverPubkey, sizeof(peer->serverPubkey));

    registry_add_connection(peer);

    LOG(PROTOCOL, "Peer[%u] connecting to %s:%s", peer->uid, peerIdStr, peer->protocol);

    request.id = peer->uid;
    request.peerid = peerIdStr;
    request.protocol = peer->protocol;

    result = sendMESG(peer->grid, MSG_CALL_REMOTE, &request);
    return connection_set_result(peer, result);
}

osdg_result_t osdg_connect_to_remote(osdg_connection_t grid, osdg_connection_t peer, const osdg_key_t peerId, const char *protocol)
{
  int ret;
  
  if ((grid->state != osdg_connected) || connection_in_use(peer))
    return osdg_wrong_state;

  ret = connection_init(peer);
  if (ret)
    return peer->errorKind;

  peer->mode =  mode_peer;
  peer->grid = grid;

  memcpy(peer->clientPubkey, grid->clientPubkey, sizeof(peer->clientPubkey));
  memcpy(peer->clientSecret, grid->clientSecret, sizeof(peer->clientSecret));
  memcpy(peer->serverPubkey, peerId, sizeof(peer->serverPubkey));
  strncpy(peer->protocol, protocol, sizeof(peer->protocol));

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

  mainloop_send_client_request(&peer->req, peer_call_remote);
  return connection_wait(peer);
}

static osdg_result_t pairing_handle_incoming_packet(struct _osdg_connection *conn,
                                                    const void *p, unsigned int length)
{
    const char *data = p;

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
        int ret;

        if (!mesg)
          return osdg_buffer_exceeded;

        payload = (struct mesg_payload *)(mesg->mesg_payload - crypto_box_BOXZEROBYTES);
        response = (struct PairingResponse *)payload->data.data;
        response->msgCode = MSG_PAIRING_RESPONSE;

        LOG(PROTOCOL, "Connection[%p] received MSG_PAIRING_CHALLENGE:", conn);
        DUMP(PROTOCOL, challenge->X, sizeof(challenge->X), "X    ");
        DUMP(PROTOCOL, challenge->nonce, sizeof(challenge->nonce), "nonce");
        DUMP(PROTOCOL, challenge->Y, sizeof(challenge->Y), "Y    ");

        l = strlen(conn->protocol);
        memcpy(buf, conn->protocol, l);
        memcpy(&buf[l], conn->clientPubkey, crypto_box_PUBLICKEYBYTES);
        memcpy(&buf[l + crypto_box_PUBLICKEYBYTES], conn->serverPubkey, crypto_box_PUBLICKEYBYTES);
        crypto_hash(buf, buf, l + crypto_box_PUBLICKEYBYTES * 2);

        memcpy(&buf[crypto_hash_BYTES], challenge->nonce, sizeof(challenge->nonce));
        crypto_hash(hash, buf, sizeof(buf));

        crypto_stream_xor(xor, challenge->Y, sizeof(challenge->Y), challenge->nonce, hash);
        crypto_scalarmult_base(base, conn->beforenmData);
        ret = crypto_scalarmult(p1, xor, base);
        if (ret)
            return osdg_crypto_core_error;

        randombytes(rnd, sizeof(rnd));
        ret = crypto_scalarmult(response->X, rnd, p1);
        if (ret)
            return osdg_crypto_core_error;

        /* This is used in both hashing rounds below, avoid copying */
        ret = crypto_scalarmult(&buf[crypto_hash_BYTES], rnd, challenge->X);
        if (ret)
            return osdg_crypto_core_error;

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
            return osdg_protocol_error;
        }

        LOG(PROTOCOL, "MSG_PAIRING_RESULT successful");

        /* There's nothing more to do here, so we close this connection. */
        connection_terminate(conn, osdg_pairing_complete);
        return osdg_no_error;
    }

    DUMP(ERRORS, data, length, "Unknown pairing message type %u", data[0]);
    return osdg_no_error;
}

static int peer_pair_remote(struct _osdg_connection *peer)
{
    PairRemote request = PAIR_REMOTE__INIT;
    char otpServerPart[SDG_MAX_OTP_BYTES];
    size_t len = strlen(peer->protocol) - 3;
    osdg_result_t result;

    /* We never send the whole OTP to the server, i guess for security.
     * We verify the complete thing during challenge-response verification */
    memcpy(otpServerPart, peer->protocol, len);
    otpServerPart[len] = 0;

    registry_add_connection(peer);
    LOG(PROTOCOL, "Peer[%u] remote pairing OTP %s", peer->uid, peer->protocol);

    request.id = peer->uid;
    request.otp = otpServerPart;

    result = sendMESG(peer->grid, MSG_PAIR_REMOTE, &request);
    return connection_set_result(peer, result);
}

osdg_result_t osdg_pair_remote(osdg_connection_t grid, osdg_connection_t peer, const char *otp)
{
    int len = 0;
    int ret;

    if ((grid->state != osdg_connected) || connection_in_use(peer))
        return osdg_wrong_state;

    /* We're reusing peer->protocol for OTP storage.
       Filter out all non-digits, counting length in the process */
    while ((*otp) && (len < SDG_MAX_OTP_BYTES))
    {
        if (isdigit(*otp))
            peer->protocol[len++] = *otp;
        otp++;
    }

    if (len < SDG_MIN_OTP_LENGTH || len >= SDG_MAX_OTP_BYTES)
    {
        peer->errorKind = osdg_invalid_parameters;
        return osdg_invalid_parameters;
    }

    /* Terminate the OTP string */
    peer->protocol[len] = 0;
    /* Don't return garbage from osdg_get_peer_id() */
    memset(peer->serverPubkey, 0, sizeof(osdg_key_t));

    memcpy(peer->clientPubkey, grid->clientPubkey, sizeof(peer->clientPubkey));
    memcpy(peer->clientSecret, grid->clientSecret, sizeof(peer->clientSecret));

    ret = connection_init(peer);
    if (ret)
        return peer->errorKind;

    peer->receiveData = pairing_handle_incoming_packet;
    peer->mode        = mode_pairing;
    peer->grid        = grid;

    mainloop_send_client_request(&peer->req, peer_pair_remote);
    return connection_wait(peer);
}

int peer_handle_remote_call_reply(struct _osdg_connection *peer, PeerReply *reply)
{
    int ret;

    if (reply->result || (!reply->peer))
    {
        LOG(CONNECTION, "Peer[%u] connection refused; code %d", reply->id, reply->result);
        peer->errorKind = osdg_connection_refused;
        connection_terminate(peer, osdg_error);
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
        connection_terminate(peer, osdg_error);
        return 0;
    }

    memcpy(peer->tunnelId, reply->peer->tunnelid.data, peer->tunnelIdSize);

    ret = connect_to_host(peer, reply->peer->server->host, reply->peer->server->port);
    if (ret == 0)
    {
        peer->errorKind = osdg_connection_failed;
        connection_terminate(peer, osdg_error);
    }

    return 0; /* We never abort grid connection */
}

osdg_result_t osdg_send_data(osdg_connection_t conn, const void *data, int size)
{
    struct packetMESG *mesg;
    struct mesg_payload *payload;

    if (conn->state != osdg_connected || conn->mode != mode_peer)
        return osdg_wrong_state;

    mesg = get_MESG_packet(conn, size);
    if (!mesg)
        return osdg_buffer_exceeded;

    payload = (struct mesg_payload *)(mesg->mesg_payload - crypto_box_BOXZEROBYTES);
    memcpy(payload->data.data, data, size);

    return send_MESG_packet(conn, mesg);
}
