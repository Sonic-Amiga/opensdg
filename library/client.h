#ifndef _INTERNAL_CLIENT_H
#define _INTERNAL_CLIENT_H

#include "opensdg.h"
#include "protocol.h"

#define BUFFER_SIZE 1536

struct _osdg_client
{
  SOCKET               sock;
  unsigned int         errorKind;
  unsigned int         errorCode;
  osdg_key_t           serverPubkey;                                /* Server's public key */
  unsigned char        clientPubkey[crypto_box_PUBLICKEYBYTES];     /* Client's long term key pair */
  const unsigned char *clientSecret;
  unsigned char        clientTempPubkey[crypto_box_PUBLICKEYBYTES]; /* Client's short term key pair */
  unsigned char        clientTempSecret[crypto_box_SECRETKEYBYTES];
  unsigned char        serverCookie[curvecp_COOKIEBYTES];
  unsigned char        beforenmData[crypto_box_BEFORENMBYTES];
  unsigned long long   nonce;
  unsigned char        buffer[BUFFER_SIZE];
};

static inline unsigned long long client_get_nonce(struct _osdg_client *client)
{
  unsigned long long nonce = client->nonce++;
  return SWAP_64(nonce); /* Our protocol wants bigendian data */
}

#endif