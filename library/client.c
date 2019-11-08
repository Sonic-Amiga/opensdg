#include <sodium.h>
#include <string.h>

#include "client.h"
#include "logging.h"
#include "protocol.h"

static inline void client_put_buffer_nolock(struct _osdg_client *client, struct osdg_buffer *buffer)
{
  buffer->next = client->bufferQueue;
  client->bufferQueue = buffer;
}

osdg_client_t osdg_client_create(const osdg_key_t private_key, unsigned int max_pdu)
{
  struct _osdg_client *client;
  unsigned int i;

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
  client->bufferSize   = max_pdu;
  client->bufferQueue  = NULL;

  pthread_mutex_init(&client->bufferMutex, NULL);
  /* Prepare some buffers */
  for (i = 0; i < 3; i++)
    client_put_buffer_nolock(client, malloc(client->bufferSize));

  /* Compute the public key */
  crypto_scalarmult_base(client->clientPubkey, private_key);

  return client;
}

int osdg_client_connect_to_socket(osdg_client_t client, SOCKET s)
{
    int res;
    struct packet_header tell;
    void *buffer;

    client->sock = s;

    /* Send initial TELL command in order to start the process */
    LOG_KEY("Public key", client->clientPubkey, sizeof(client->clientPubkey));
    LOG_KEY("Private key", client->clientSecret, crypto_box_SECRETKEYBYTES);

    build_header(&tell, CMD_TELL, sizeof(tell));
    res = send_packet(&tell, client);
    if (res != 0)
        return res;

    buffer = client_get_buffer(client);
    res = blocking_loop(buffer, client);
    client_put_buffer(client, buffer);
    return res;
}

void osdg_client_destroy(osdg_client_t client)
{
  struct osdg_buffer *buffer, *next;

  for (buffer = client->bufferQueue; buffer; buffer = next)
  {
    next = buffer->next;
    free(buffer);
  }

  pthread_mutex_destroy(&client->bufferMutex);
  free(client);
}

enum osdg_error_kind osdg_client_get_error_kind(osdg_client_t client)
{
  return client->errorKind;
}

int osdg_client_get_error_code(osdg_client_t client)
{
  return client->errorCode;
}

void *client_get_buffer(struct _osdg_client *client)
{
  struct osdg_buffer *buffer;

  pthread_mutex_lock(&client->bufferMutex);

  buffer = client->bufferQueue;
  if (buffer)
    client->bufferQueue = buffer->next;

  pthread_mutex_unlock(&client->bufferMutex);

  if (!buffer)
    buffer = malloc(client->bufferSize);

  return buffer;
}

void client_put_buffer(struct _osdg_client *client, void *ptr)
{
  pthread_mutex_lock(&client->bufferMutex);
  client_put_buffer_nolock(client, ptr);
  pthread_mutex_unlock(&client->bufferMutex);
}

