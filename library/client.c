#include <sodium.h>
#include <string.h>

#include "client.h"
#include "logging.h"
#include "mainloop.h"
#include "protocol.h"
#include "socket.h"

/* Peers table increment */
#define PEERS_CHUNK 64

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

  client->errorKind     = osdg_no_error;
  client->errorCode     = 0;
  client->nonce         = 0;
  client->clientSecret  = private_key;
  client->bufferSize    = max_pdu;
  client->bufferQueue   = NULL;
  client->receiveBuffer = NULL;
  client->numPeers      = PEERS_CHUNK;

  pthread_mutex_init(&client->bufferMutex, NULL);
  pthread_mutex_init(&client->peersMutex, NULL);

  /* Prepare some buffers */
  for (i = 0; i < 3; i++)
    client_put_buffer_nolock(client, malloc(client->bufferSize));

  /* Allocate peers table */
  client->peers = calloc(client->numPeers, sizeof(void *));

  /* Compute the public key */
  crypto_scalarmult_base(client->clientPubkey, private_key);

  return client;
}

static void connection_shutdown(struct _osdg_client *client)
{
    unregister_connection(client);

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

int osdg_client_connect_to_server(osdg_client_t client, const struct osdg_endpoint *servers)
{
  int res = -1;
  unsigned int nServers, left, i;
  const struct osdg_endpoint **list, **randomized;

  for (nServers = 0; servers[nServers].host; nServers++);
  if (nServers == 0)
  {
    client->errorKind = osdg_invalid_parameters;
    return -1;
  }

  /* Permute servers in random order in order to distribute the load */
  list = malloc(nServers * sizeof(void *));
  for (i = 0; i < nServers; i++)
    list[i] = &servers[i];

  randomized = malloc(nServers * sizeof(void *));
  left = nServers;
  for (i = 0; i < nServers; i++)
  {
    unsigned int idx = rand() / ((((unsigned int)RAND_MAX) + 1) / left);

    randomized[i] = list[idx];
    left--;
    list[idx] = list[left];
  }

  free((void *)list);

  for (i = 0; i < nServers; i++)
  {
    res = try_to_connect(client, randomized[i]->host, randomized[i]->port);

    if (res < 0)
      break; /* Serious error, give up */

    if (res == 1)
    {
      register_connection(client);

      res = sendTELL(client);
      if (!res)
        break;

      connection_shutdown(client);
      res = -1;
    }
  }

  free((void *)randomized);

  if (res)
    client->errorKind = osdg_connection_failed;

  return res;
}

void osdg_client_destroy(osdg_client_t client)
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

void connection_read_data(struct _osdg_client *conn)
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

unsigned int client_register_peer(struct _osdg_client *client, struct _osdg_peer *peer)
{
  unsigned int i;

  pthread_mutex_lock(&client->peersMutex);

  for (i = 0; i < client->numPeers; i++)
  {
    if (!client->peers[i])
      break;
  }

  if (i == client->numPeers)
  {
    unsigned int numPeers = client->numPeers + PEERS_CHUNK;

    client->peers = realloc(client->peers, client->numPeers);
    client->numPeers = numPeers;
    memset(&client->peers[numPeers], 0, sizeof(void *) * PEERS_CHUNK);
  }

  client->peers[i] = peer;

  pthread_mutex_unlock(&client->peersMutex);
  return i;
}

void client_unregister_peer(struct _osdg_client *client, unsigned int id)
{
  pthread_mutex_lock(&client->peersMutex);
  client->peers[id] = NULL;
  pthread_mutex_unlock(&client->peersMutex);
}

struct _osdg_peer *client_find_peer(struct _osdg_client *client, unsigned int id)
{
  struct _osdg_peer *peer;

  pthread_mutex_lock(&client->peersMutex);
  peer = (id < client->numPeers) ? client->peers[id] : NULL;
  pthread_mutex_unlock(&client->peersMutex);

  return peer;
}

