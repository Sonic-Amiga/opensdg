#include <sodium.h>
#include <string.h>

#include "client.h"
#include "logging.h"
#include "mainloop.h"
#include "protocol.h"
#include "socket.h"
#include "registry.h"

/* Our key pair */
unsigned char clientPubkey[crypto_box_PUBLICKEYBYTES];
unsigned char clientSecret[crypto_box_SECRETKEYBYTES];

int osdg_init(const osdg_key_t private_key)
{
    if (sodium_init() == -1)
    {
        LOG(ERRORS, "libsodium init failed");
        return -1;
    }

    registry_init();

    /* TODO: Move Winsock init here */

    memcpy(clientSecret, private_key, sizeof(clientSecret));
    /* Compute the public key */
    crypto_scalarmult_base(clientPubkey, clientSecret);

    return 0;
}

static inline void client_put_buffer_nolock(struct _osdg_connection *client, struct osdg_buffer *buffer)
{
  buffer->next = client->bufferQueue;
  client->bufferQueue = buffer;
}

int connection_allocate_buffers(struct _osdg_connection *conn)
{
    int i;

    if (conn->haveBuffers)
        return 0;

    for (i = 0; i < 3; i++)
    {
        void *buffer = malloc(conn->bufferSize);

        if (!buffer)
        {
            conn->errorKind = osdg_memory_error;
            return -1;
        }

        client_put_buffer_nolock(conn, buffer);
    }

    conn->haveBuffers = 1;
    return 0;
}

osdg_connection_t osdg_connection_create(void)
{
  struct _osdg_connection *client = malloc(sizeof(struct _osdg_connection));
  
  if (!client)
    return NULL;

  client->uid           = -1;
  client->errorKind     = osdg_no_error;
  client->errorCode     = 0;
  client->mode          = mode_none;
  client->receiveData   = NULL;
  client->nonce         = 0;
  client->tunnelId      = NULL;
  client->haveBuffers   = 0;
  /*
   * This buffer size is used by original mdglib from DEVISmart Android APK,
   * so we're using it as a default.
   */
  client->bufferSize    = 1536;
  client->bufferQueue   = NULL;
  client->receiveBuffer = NULL;

  pthread_mutex_init(&client->bufferMutex, NULL);

  return client;
}

void connection_shutdown(struct _osdg_connection *client)
{
    registry_remove_connection(client);

    if (client->tunnelId)
    {
        free(client->tunnelId);
        client->tunnelId = NULL;
    }

    if (client->receiveBuffer)
    {
        client_put_buffer(client, client->receiveBuffer);
        client->receiveBuffer = NULL;
    }

    if (client->sock != -1)
    {
        closesocket(client->sock);
        client->sock = -1;
    }
}

void osdg_connection_destroy(osdg_connection_t client)
{
  struct osdg_buffer *buffer, *next;

  connection_shutdown(client);

  for (buffer = client->bufferQueue; buffer; buffer = next)
  {
    next = buffer->next;
    free(buffer);
  }

  pthread_mutex_destroy(&client->bufferMutex);
  free(client);
}

enum osdg_error_kind osdg_get_error_kind(osdg_connection_t client)
{
  return client->errorKind;
}

int osdg_get_error_code(osdg_connection_t client)
{
  return client->errorCode;
}

const unsigned char *osdg_get_peer_id(osdg_connection_t conn)
{
    return conn->serverPubkey;
}

int osdg_set_receive_data_callback(osdg_connection_t client, osdg_receive_cb_t f)
{
    /* Grid connections have internal data handler, don't screw them up */
    if (client->mode == mode_grid)
        return -1;

    client->receiveData = f;
    return 0;
}

void *client_get_buffer(struct _osdg_connection *client)
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

void client_put_buffer(struct _osdg_connection *client, void *ptr)
{
  pthread_mutex_lock(&client->bufferMutex);
  client_put_buffer_nolock(client, ptr);
  pthread_mutex_unlock(&client->bufferMutex);
}

void connection_read_data(struct _osdg_connection *conn)
{
    int ret;

    if (!conn->receiveBuffer)
    {
        conn->receiveBuffer = client_get_buffer(conn);
        conn->bytesLeft = 0;
    }

    ret = receive_packet(conn);
    if (ret)
    {
        LOG(ERRORS, "Connection %p died", conn);
        connection_shutdown(conn);
        /* TODO: Implement some notification here */
    }
}

int connection_handle_data(struct _osdg_connection *conn, const unsigned char *data, unsigned int length)
{
    unsigned int discard = conn->discardFirstBytes;
    conn->discardFirstBytes = 0; /* Discarded */

    if (length <= discard)
        return 0; /* Just in case, we shouldn't get here */

    data   += discard;
    length -= discard;

    return conn->receiveData ? conn->receiveData(conn, data, length) : 0;
}
