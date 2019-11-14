#include <errno.h>
#include <sodium.h>
#include <string.h>
#ifndef _WIN32
#include <sys/socket.h>
#endif

#include "client.h"
#include "logging.h"
#include "socket.h"
#include "protocol.h"
#include "protocol.pb-c.h"

static inline void dump_packet(const char *str, const struct packet_header *header)
{
    const unsigned char *buffer = (unsigned char *)header;

    DUMP(PACKETS, buffer + sizeof(struct packet_header), PAYLOAD_SIZE(header),
         "%s: %.4s", str, &header->command);
}

int send_packet(struct packet_header *header, struct _osdg_client *client)
{
    dump_packet("Sending", header);
    return send_data((const unsigned char *)header, PACKET_SIZE(header), client);
}

static void *decryptMESG(struct packet_header *header, struct _osdg_client *client, const char *nonce_prefix)
{
    struct packetMESG *mesg = (struct packetMESG *)header;
    unsigned char *payload = mesg->mesg_payload - crypto_box_BOXZEROBYTES;
    unsigned int length = MESG_CIPHERTEXT_SIZE(header);
    union curvecp_nonce nonce;
    int res;

    build_short_term_nonce(&nonce, nonce_prefix, mesg->nonce);
    /* This will overwrite header and nonce */
    zero_outer_pad(mesg->mesg_payload);
    /* We don't want to bother with malloc(), decrypt in place */
    res = crypto_box_open_afternm(payload, payload, length + crypto_box_BOXZEROBYTES,
        nonce.data, client->beforenmData);
    if (res)
    {
        client->errorKind = osdg_decryption_error;
        return NULL;
    } else
    {
        return payload;
    }
}

static inline unsigned long long client_get_nonce(struct _osdg_client *client)
{
    unsigned long long nonce = client->nonce++;
    return SWAP_64(nonce); /* Our protocol wants bigendian data */
}

int receive_packet(struct _osdg_client *client)
{
    int ret;
    unsigned int size;
    struct packet_header *header;

    if (client->bytesLeft == 0)
    {
        /* Every packet is prefixed with length, read it first */
        client->bytesReceived = 0;
        client->bytesLeft = sizeof(unsigned short);
    }

    ret = receive_data(client);

    if (ret == sizeof(unsigned short))
    {
        /* Data size is bigendian */
        size = (client->receiveBuffer[0] << 8) | client->receiveBuffer[1];

        if (size + sizeof(unsigned short) > client->bufferSize)
        {
            LOG(ERRORS, "Buffer size of %u exceeded; incoming packet size is %u",
                client->bufferSize, size);
            client->errorKind = osdg_buffer_exceeded;
            return -1;
        }

        client->bytesLeft = size;
        ret = receive_data(client);
    }

    if (ret <= 0)
        return ret;

    header = (struct packet_header *)client->receiveBuffer;
    if (header->magic != PACKET_MAGIC)
    {
        LOG(ERRORS, "Invalid packet received, wrong magic");
        client->errorKind = osdg_protocol_error;
        return -1;
    }

    dump_packet("Received", header);

    if (header->command == CMD_WELC)
    {
        struct packetWELC *welc = (struct packetWELC *)header;
        struct packetHELO helo;
        union curvecp_nonce nonce;
        unsigned char zeroMsg[sizeof(helo.ciphertext) + crypto_box_BOXZEROBYTES];

        memcpy(client->serverPubkey, welc->serverKey, sizeof(welc->serverKey));
        crypto_box_keypair(client->clientTempPubkey, client->clientTempSecret);
        DUMP(PROTOCOL, client->clientTempPubkey, sizeof(client->clientTempPubkey),
             "Created short-term public key");
        DUMP(PROTOCOL, client->clientTempSecret, sizeof(client->clientTempSecret),
            "Created short-term secret key");

        build_short_term_nonce(&nonce, "CurveCP-client-H", client_get_nonce(client));
        memset(zeroMsg, 0, sizeof(zeroMsg));

        build_header(&helo.header, CMD_HELO, sizeof(helo));

        /*
            * Decrement ciphertext pointer in order to get first crypto_box_BOXZEROBYTES
            * stripped. We will overwrite them later by copying public key and nonce.
            */
        ret = crypto_box(helo.ciphertext - crypto_box_BOXZEROBYTES, zeroMsg, sizeof(zeroMsg),
                         nonce.data, client->serverPubkey, client->clientTempSecret);
        if (ret)
        {
            client->errorKind = osdg_encryption_error;
            return -1;
        }

        memcpy(helo.clientPubkey, client->clientTempPubkey, sizeof(helo.clientPubkey));
        helo.nonce = nonce.value[2];

        return send_packet(&helo.header, client);
    }
    else if (header->command == CMD_COOK)
    {
        struct packetCOOK *cook = (struct packetCOOK *)header;
        struct curvecp_vouch_outer *outerData;
        union curvecp_nonce nonce;
        struct curvecp_cookie cookie;
        struct curvecp_vouch_inner innerData;
        struct packetVOCH *voch;
        int certDataSize;

        build_long_term_nonce(&nonce, "CurveCPK", cook->nonce);

        /* Replace nonce with padding zeroes in place and decrypt the message */
        zero_outer_pad(cook->curvecp_cookie);
        ret = crypto_box_open((unsigned char *)&cookie, cook->curvecp_cookie - crypto_box_BOXZEROBYTES,
                              sizeof(cookie), nonce.data, client->serverPubkey, client->clientTempSecret);
        if (ret)
        {
            client->errorKind = osdg_decryption_error;
            return -1;
        }

        DUMP(PROTOCOL, cookie.serverShortTermPubkey, sizeof(cookie.serverShortTermPubkey),
             "Short-term server pubkey");
        DUMP(PROTOCOL, cookie.cookie, sizeof(cookie.cookie), "Server cookie");

        memcpy(client->serverCookie, cookie.cookie, sizeof(cookie.cookie));
        ret = crypto_box_beforenm(client->beforenmData, cookie.serverShortTermPubkey, client->clientTempSecret);
        if (ret)
        {
            client->errorKind = osdg_encryption_error;
            return -1;
        }

        /*
         * The packet has variable length, so for simplicity we will get a buffer and
         * build and encrypt the packet in place
         */
        voch = client_get_buffer(client);
        outerData = (struct curvecp_vouch_outer *)(voch->curvecp_vouch_outer - crypto_box_BOXZEROBYTES);

        /* Build the inner crypto box */
        zero_pad(innerData.outerPad);
        memcpy(innerData.clientPubkey, client->clientTempPubkey, sizeof(innerData.clientPubkey));

        build_random_long_term_nonce(&nonce, "CurveCPV");
        ret = crypto_box(outerData->curvecp_vouch_inner - crypto_box_BOXZEROBYTES,
                         (unsigned char *)&innerData, sizeof(innerData), nonce.data,
                         client->serverPubkey, clientSecret);
        if (ret)
        {
            client_put_buffer(client, voch);
            client->errorKind = osdg_encryption_error;
            return -1;
        }

        /* Now compose the outer data */
        zero_pad(outerData->outerPad);
        memcpy(outerData->clientPubkey, clientPubkey, sizeof(outerData->clientPubkey));
        outerData->nonce[0] = nonce.value[1];
        outerData->nonce[1] = nonce.value[2];

        if (client->mode == mode_grid)
        {
            /*
             * License key is appended to VOCH packet in a form of key-value pair.
             * Unlike MESG this is not protobuf, but a fixed structure. An empty
             * license key is reported as all zeroes.
             * Actually the grid (at least DEVISmart one) accepts VOCH packets
             * without this optional data just fine, but we fully replicate the
             * original library just in case, for better compatibility.
             */
            struct certificate_data *cert = (struct certificate_data *)outerData->certificate;

            outerData->haveCertificate = 1;
            certDataSize = sizeof(struct certificate_data);

            cert->prefixLength = 11; /* strlen("certificate") */
            strcpy(cert->prefix, "certificate");
            cert->keyLength = sizeof(cert->key);
            memset(cert->key, 0, sizeof(cert->key));
        }
        else
        {
           /*
            * When connecting to a peer the original library does not report
            * the license key, we do the same.
            */
            outerData->haveCertificate = 0;
            certDataSize = 0;
        }

        /* And now build the packet */
        build_header(&voch->header, CMD_VOCH, sizeof(struct packetVOCH) + certDataSize);

        build_short_term_nonce(&nonce, "CurveCP-client-I", client_get_nonce(client));
        ret = crypto_box_afternm((unsigned char *)outerData, (unsigned char *)outerData,
                                 sizeof(struct curvecp_vouch_outer) + certDataSize,
                                 nonce.data, client->beforenmData);
        if (ret)
        {
            client_put_buffer(client, voch);
            client->errorKind = osdg_encryption_error;
            return -1;
        }

        memcpy(voch->cookie, client->serverCookie, sizeof(voch->cookie));
        voch->nonce = nonce.value[2];

        ret = send_packet(&voch->header, client);

        client_put_buffer(client, voch);
        return ret;
    }
    else if (header->command == CMD_REDY)
    {
        /*
         * Decryption of REDY packet is identical to MESG with the only difference
         * being nonce prefix
         */
        struct redy_payload *payload = decryptMESG(header, client, "CurveCP-server-R");
        unsigned int length;
        ProtocolVersion protocolVer;

        if (!payload)
            return -1;

        /*
         * REDY payload from DEVISmart cloud consists of 16 zeroes of padding and
         * then one more zero byte. Original mdglib gets a pointer to that byte and
         * calls some function by pointer, which performs some verification and
         * can return error, causing connection abort. This function also gets
         * license key information.
         * Perhaps this has something to do with license validation. We don't know
         * and don't care.
         */
        length = MESG_CIPHERTEXT_SIZE(header) - crypto_box_BOXZEROBYTES;
        DUMP(PROTOCOL, payload->unknown, length, "Got REDY response (%u bytes)", length);

        /* Now let's do protocol version handshake */
        protocol_version__init(&protocolVer);
        protocolVer.magic = PROTOCOL_VERSION_MAGIC;
        protocolVer.major = PROTOCOL_VERSION_MAJOR;
        protocolVer.minor = PROTOCOL_VERSION_MINOR;
        /* TODO: Implement client properties */

        return sendMESG(client, MSG_PROTOCOL_VERSION, &protocolVer);
    }
    else if (header->command == CMD_MESG)
    {
        struct mesg_payload *payload = decryptMESG(header, client, "CurveCP-server-M");
        unsigned int length;

        if (!payload)
            return -1;

        length = SWAP_16(payload->dataSize) - sizeof(payload->dataType);

        if (payload->dataType == MSG_PROTOCOL_VERSION)
        {
            ProtocolVersion *protocolVer = protocol_version__unpack(NULL, length, payload->data);

            if (!protocolVer)
            {
                LOG(ERRORS, "MSG_PROTOCOL_VERSION protobuf decoding error");
                client->errorKind = osdg_protocol_error;
                return -1;
            }

            if (protocolVer->magic != PROTOCOL_VERSION_MAGIC)
            {
                LOG(ERRORS, "Incorrect protocol version magic 0x%08X", protocolVer->magic);
            }
            else if (protocolVer->major != PROTOCOL_VERSION_MAJOR || protocolVer->minor != PROTOCOL_VERSION_MINOR)
            {
                LOG(ERRORS, "Unsupported server protocol version %u.%u", protocolVer->major, protocolVer->minor);
                ret = -1;
            }
            else
            {
                LOG(PROTOCOL, "Using protocol version %u.%u", protocolVer->major, protocolVer->minor);
                ret = 0; /* We're done with the handshake */
                /* TODO: Implement user notification */
            }

            protocol_version__free_unpacked(protocolVer, NULL);

            if (ret)
            {
                client->errorKind = osdg_protocol_error;
                return ret;
            }
        }
        else if (payload->dataType = MSG_REMOTE_REPLY)
        {
            PeerReply *reply = peer_reply__unpack(NULL, length, payload->data);

            if (!reply)
            {
                DUMP(ERRORS, payload->data, length, "MSG_REMOTE_REPLY protobuf decoding error");
                return 0; /* Ignore */
            }

            ret = peer_handle_remote_call_reply(reply);
            peer_reply__free_unpacked(reply, NULL);

            return ret;
        }
        else
        {
            DUMP(PROTOCOL, payload->data, length,
                 "Unhandled MESG type %u length %u bytes:", payload->dataType, length);
        }
    }
    else
    {
        LOG(ERRORS, "Unknown packet received; ignoring");
    }

    return 0;
}

int sendTELL(struct _osdg_client *client)
{
    struct packet_header tell;

    DUMP(PROTOCOL, clientPubkey, sizeof(clientPubkey), "Using public key");
    DUMP(PROTOCOL, clientSecret, sizeof(clientSecret), "Using private key");

    build_header(&tell, CMD_TELL, sizeof(tell));
    return send_packet(&tell, client);
}

int sendMESG(struct _osdg_client *client, unsigned char dataType, const void *data)
{
  size_t dataSize = protobuf_c_message_get_packed_size(data);
  size_t packetSize = sizeof(struct packetMESG) + dataSize;
  struct packetMESG *mesg;
  struct mesg_payload *payload;
  union curvecp_nonce nonce;
  int res;

  if (packetSize > client->bufferSize)
  {
    LOG(ERRORS, "Buffer size of %u exceeded; outgoing packet size is %u",
        client->bufferSize, packetSize);
    client->errorKind = osdg_buffer_exceeded;
    return -1;
  }

  /* We will build and encrypt the box in place, so need only one buffer */
  mesg = client_get_buffer(client);
  payload = (struct mesg_payload *)(mesg->mesg_payload - crypto_box_BOXZEROBYTES);

  zero_pad(payload->outerPad);
  payload->dataSize = SWAP_16(dataSize + sizeof(payload->dataType));
  payload->dataType = dataType;
  protobuf_c_message_pack(data, payload->data);

  build_short_term_nonce(&nonce, "CurveCP-client-M", client_get_nonce(client));
  res = crypto_box_afternm((unsigned char *)payload, (unsigned char *)payload,
                           sizeof(struct mesg_payload) + dataSize,
                           nonce.data, client->beforenmData);
  if (res)
  {
    client->errorKind = osdg_encryption_error;
  }
  else
  {
    build_header(&mesg->header, CMD_MESG, packetSize);
    mesg->nonce = nonce.value[2];
    res = send_packet(&mesg->header, client);
  }

  client_put_buffer(client, mesg);
  return res;
}
