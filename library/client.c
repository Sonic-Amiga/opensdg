#include <sodium.h>
#include <Winsock2.h>

#include "client.h"
#include "logging.h"
#include "protocol.h"

// crypto_scalarmult_base - compute public from private

osdg_client_t osdg_client_create(const osdg_key_t private_key)
{
  struct _osdg_client *client;

  if (sodium_init() == -1)
  {
    LOG(ERRORS, "libsodium init failed");
    return NULL;
  }

  client = malloc(sizeof(struct _osdg_client));
  if (!client)
    return NULL;

  client->errorKind    = osdg_no_error;
  client->errorCode    = 0;
  client->nonce        = 0;
  client->clientSecret = private_key;

  /* Compute the public key */
  crypto_scalarmult_base(client->clientPubkey, private_key);

  return client;
}

int osdg_client_connect_to_socket(osdg_client_t client, SOCKET s)
{
    int res;
    struct packet_header tell;

    client->sock = s;

    /* Send initial TELL command in order to start the process */
    LOG_KEY("Public key", client->clientPubkey, sizeof(client->clientPubkey));
    LOG_KEY("Private key", client->clientSecret, crypto_box_SECRETKEYBYTES);

    build_header(&tell, CMD_TELL, sizeof(tell));
    res = send_packet(&tell, client);
    if (res != 0)
        return res;

    return blocking_loop(client->buffer, client);
}

void osdg_client_destroy(osdg_client_t client)
{
  free(client);
}

enum osdg_error_king osdg_client_get_error_kind(osdg_client_t client)
{
  return client->errorKind;
}

int osdg_client_get_error_code(osdg_client_t client)
{
  return client->errorCode;
}
