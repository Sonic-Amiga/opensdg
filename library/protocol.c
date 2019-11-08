#include <errno.h>
#include <sodium.h>
#include <string.h>
#ifndef _WIN32
#include <sys/socket.h>
#endif

#include "client.h"
#include "logging.h"
#include "protocol.h"

#ifndef _WIN32

static inline int WSAGetLastError(void)
{
  return errno;
}

#endif

static inline void set_socket_error(struct _osdg_client *client)
{
    client->errorKind = osdg_socket_error;
    client->errorCode = WSAGetLastError();
}

static int receive_data(struct _osdg_client *client, unsigned char *buffer, int size)
{
    int ret;

    do
    {
        ret = recv(client->sock, buffer, size, 0);
        if (ret < 0)
        {
            set_socket_error(client);
            return ret;
        }
        buffer += ret;
        size -= ret;
    } while (size);

    return 0;
}

void dump_packet(const char *str, const struct packet_header *header)
{
    const char *buffer = (char *)header;

    _log(LOG_PROTOCOL, "%s: %.4s", str, &header->command);
    Dump(buffer + sizeof(struct packet_header), PAYLOAD_SIZE(header));
}

void dump_key(const char *str, const unsigned char *key, unsigned int size)
{
  char buffer[193];

  sodium_bin2hex(buffer, sizeof(buffer), key, size);
  _log(LOG_PROTOCOL, "%s: %s", str, buffer);
}

int send_packet(struct packet_header *header, struct _osdg_client *client)
{
    const char *buffer = (char *)header;
    int size = PACKET_SIZE(header);
    int ret;

    LOG_PACKET("Sending", header);

    do
    {
        ret = send(client->sock, buffer, size, 0);
        if (ret < 0)
        {
            set_socket_error(client);
            return ret;
        }
        size -= ret;
        buffer += ret;
    } while (size);

    return 0;
}

int receive_packet(unsigned char *buffer, struct _osdg_client *client)
{
    struct packet_header *header = (struct packet_header *)buffer;
    int ret = receive_data(client, buffer, sizeof(struct packet_header));
    int size;

    if (ret)
        return ret;

    if (header->magic != PACKET_MAGIC)
    {
      LOG(ERRORS, "Invalid packet received, wrong magic");
      client->errorKind = osdg_protocol_error;
      return -1;
    }

    size = PACKET_SIZE(header);
    if (size > client->bufferSize)
    {
      LOG(ERRORS, "Buffer size of %u exceeded; packet size is %u",
          client->bufferSize, size);
      client->errorKind = osdg_buffer_exceeded;
      return -1;
    }

    size = PAYLOAD_SIZE(header);
    if (size == 0)
        return 0;

    ret = receive_data(client, buffer + sizeof(struct packet_header), size);
    if (ret)
        return ret;

    LOG_PACKET("Received", header);
    return size;
}

static void *decodeMESG(struct packet_header *header, struct _osdg_client *client, const char *nonce_prefix)
{
    struct packetMESG *mesg = (struct packetMESG *)header;
    unsigned int length = MESG_CIPHERTEXT_SIZE(header);
    union curvecp_nonce nonce;
    int res;

    build_short_term_nonce(&nonce, nonce_prefix, mesg->nonce);
    /* This will overwrite header and nonce */
    memset(mesg->ciphertext - crypto_box_BOXZEROBYTES, 0, crypto_box_BOXZEROBYTES);
    /* We don't want to bother with malloc(), decrypt in place */
    res = crypto_box_open_afternm(mesg->ciphertext - crypto_box_BOXZEROBYTES,
                                  mesg->ciphertext - crypto_box_BOXZEROBYTES,
                                  length + crypto_box_BOXZEROBYTES, nonce.data, client->beforenmData);
    if (res)
    {
        client->errorKind = osdg_decryption_error;
        return NULL;
    }
    else
    {
        return mesg->ciphertext;
    }
}

int blocking_loop(unsigned char *buffer, struct _osdg_client *client)
{
  int res;

  do
  {
    struct packet_header *header = (struct packet_header *)buffer;

    res = receive_packet(buffer, client);
    if (res < 0)
      return res;

    if (header->command == CMD_WELC)
    {
      struct packetWELC *welc = (struct packetWELC *)header;
      struct packetHELO helo;
      union curvecp_nonce nonce;
      unsigned char zeroMsg[sizeof(helo.ciphertext) + crypto_box_BOXZEROBYTES];

      memcpy(client->serverPubkey, welc->serverKey, sizeof(welc->serverKey));
      crypto_box_keypair(client->clientTempPubkey, client->clientTempSecret);
      LOG_KEY("Created short-term public key", client->clientTempPubkey, sizeof(client->clientTempPubkey));
      LOG_KEY("Created short-term secret key", client->clientTempSecret, sizeof(client->clientTempSecret));

      build_short_term_nonce(&nonce, "CurveCP-client-H", client_get_nonce(client));
      memset(zeroMsg, 0, sizeof(zeroMsg));

      build_header(&helo.header, CMD_HELO, sizeof(helo));

      /*
       * Decrement ciphertext pointer in order to get first crypto_box_BOXZEROBYTES
       * stripped. We will overwrite them later by copying public key and nonce.
       */
      res = crypto_box(helo.ciphertext - crypto_box_BOXZEROBYTES, zeroMsg, sizeof(zeroMsg),
                       nonce.data, client->serverPubkey, client->clientTempSecret);
      if (res)
      {
        client->errorKind = osdg_encryption_error;
        return res;
      }

      memcpy(helo.clientPubkey, client->clientTempPubkey, sizeof(helo.clientPubkey));
      helo.nonce = nonce.value[2];

      res = send_packet(&helo.header, client);
    }
    else if (header->command == CMD_COOK)
    {
      struct packetCOOK *cook = (struct packetCOOK *)header;
      union curvecp_nonce nonce;
      struct curvecp_cookie cookie;
      struct curvecp_vouch_inner innerData;
      struct curvecp_vouch_outer outerData;
      struct packetVOCH voch;

      build_long_term_nonce(&nonce, "CurveCPK", cook->nonce);

      /* Replace nonce with padding zeroes in place and decrypt the message */
      memset(cook->nonce, 0, crypto_box_BOXZEROBYTES);
      res = crypto_box_open((unsigned char *)&cookie, (unsigned char *)cook->nonce, 0xA0, nonce.data,
                            client->serverPubkey, client->clientTempSecret);
      if (res)
      {
        client->errorKind = osdg_decryption_error;
        return res;
      }

      LOG_KEY("Short-term server pubkey", cookie.serverShortTermPubkey, sizeof(cookie.serverShortTermPubkey));
      LOG_KEY("Server cookie", cookie.cookie, sizeof(cookie.cookie));

      memcpy(client->serverCookie, cookie.cookie, sizeof(cookie.cookie));
      res = crypto_box_beforenm(client->beforenmData, cookie.serverShortTermPubkey, client->clientTempSecret);
      if (res)
      {
        client->errorKind = osdg_encryption_error;
        return res;
      }

      /* Build the inner crypto box */
      memset(innerData.outerPad, 0, sizeof(innerData.outerPad) + sizeof(innerData.innerPad));
      memcpy(innerData.clientPubkey, client->clientTempPubkey, sizeof(innerData.clientPubkey));

      build_random_long_term_nonce(&nonce, "CurveCPV");
      res = crypto_box(outerData.curvecp_vouch_inner - crypto_box_BOXZEROBYTES,
                       (unsigned char *)&innerData, sizeof(innerData), nonce.data,
                       client->serverPubkey, client->clientSecret);
      if (res)
      {
        client->errorKind = osdg_encryption_error;
        return res;
      }

      /* Now compose the outer data */
      memset(outerData.outerPad, 0, sizeof(outerData.outerPad) + sizeof(outerData.innerPad));
      memcpy(outerData.clientPubkey, client->clientPubkey, sizeof(outerData.clientPubkey));
      outerData.nonce[0]      = nonce.value[1];
      outerData.nonce[1]      = nonce.value[2];
      /*
       * License key is appended to VOCH packet in a form of key-value pair.
       * Unlike MESG this is not protobuf, but a much simpler encoding.
       * An empty license key is reported as all zeroes.
       */
      outerData.certStrType   = 1; /* string type ? */
      outerData.certStrLength = sizeof(outerData.certStr);
      memcpy(outerData.certStr, "certificate", sizeof(outerData.certStr));
      outerData.valueType     = 0; /* byte array type ? */
      outerData.valueLength   = sizeof(outerData.license);
      memset(outerData.license, 0, sizeof(outerData.license));

      /* And now build the packet */
      build_header(&voch.header, CMD_VOCH, sizeof(voch));

      build_short_term_nonce(&nonce, "CurveCP-client-I", client_get_nonce(client));
      res = crypto_box_afternm(voch.curvecp_vouch_outer - crypto_box_BOXZEROBYTES,
                               (unsigned char *)&outerData, sizeof(outerData), nonce.data,
                               client->beforenmData);
      if (res)
      {
        client->errorKind = osdg_encryption_error;
        return res;
      }

      memcpy(voch.cookie, client->serverCookie, sizeof(voch.cookie));
      voch.nonce = nonce.value[2];

      res = send_packet(&voch.header, client);
    }
    else if (header->command == CMD_REDY)
    {
      unsigned int length = MESG_CIPHERTEXT_SIZE(header);
      void *payload = decodeMESG(header, client, "CurveCP-server-R");

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
      _log(LOG_PROTOCOL, "Got REDY response (%d bytes):", length);
      Dump(payload, length);

      return 0;
    }
    else if (header->command == CMD_MESG)
    {
      unsigned int length = MESG_CIPHERTEXT_SIZE(header);
      void *payload = decodeMESG(header, client, "CurveCP-server-M");

      if (!payload)
        return -1;

      _log(LOG_PROTOCOL, "Got MESG data (%d bytes):", length);
      Dump(payload, length);
    }
    else
    {
      LOG(ERRORS, "Unknown packet received; not replying");
    }
  } while (res >= 0);

  return res;
}

int sendMESG(struct _osdg_client *client, const void *data, int size)
{
  struct packetMESG *mesg = client_get_buffer(client);
  union curvecp_nonce nonce;
  int res;

  memcpy(mesg->ciphertext, data, size);

  build_short_term_nonce(&nonce, "CurveCP-client-M", client_get_nonce(client));
  res = crypto_box_afternm(mesg->ciphertext - crypto_box_BOXZEROBYTES,
                           mesg->ciphertext - crypto_box_BOXZEROBYTES,
                           size + crypto_box_BOXZEROBYTES, nonce.data, client->beforenmData);
  if (res)
  {
    client->errorKind = osdg_encryption_error;
  }
  else
  {
    build_header(&mesg->header, CMD_MESG, sizeof(struct packetMESG) + size);
    mesg->nonce = nonce.value[2];
    res = send_packet(&mesg->header, client);
  }

  client_put_buffer(client, mesg);
  return res;
}

