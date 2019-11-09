#include <netdb.h>
#include <sodium.h>
#include <string.h>

#include "client.h"
#include "logging.h"
#include "protocol.h"
#include "socket.h"

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

static int osdg_client_try_to_connect(struct _osdg_client *client, const struct osdg_endpoint *server)
{
  struct addrinfo *addr, *ai;
  int res;
  SOCKET s;
  
  res = getaddrinfo(server->host, NULL, NULL, &addr);
  if (res)
  {
    LOG(CONNECTION, "Failed to resolve %s: %s", server->host, gai_strerror(res));
    return res;
  }

  res = -1;

  for (ai = addr; ai; ai = ai->ai_next)
  {
    struct sockaddr *addr = ai->ai_addr;

    if (addr->sa_family == AF_INET)
    {
      ((struct sockaddr_in *)addr)->sin_port = htons(server->port);
    }
    else if (addr->sa_family == AF_INET6)
    {
      ((struct sockaddr_in6 *)addr)->sin6_port = htons(server->port);
    }
    else
    {
      LOG(CONNECTION, "Ignoring unknown address family %u for host %s", addr->sa_family, server->host);
      continue;
    }

    s = socket(addr->sa_family, SOCK_STREAM, 0);
    if (s < 0)
    {
      set_socket_error(client);
      return -1;
    }

    res = connect(s, addr, ai->ai_addrlen);
    if (res == 0)
    {
      LOG(CONNECTION, "Connected to %s:%u", server->host, server->port);
      client->sock = s;
      break;
    }

    if (log_mask & LOG_CONNECTION)
    {      
      char *err = sock_errstr();

      _log(LOG_CONNECTION, "Failed to connect to %s:%u: %s", server->host, server->port, err);
      free_errstr(err);
    }

    closesocket(s);
  }

  freeaddrinfo(addr);
  return res;
}

static void client_close_socket(struct _osdg_client *client)
{
  if (client->sock != -1)
  {
    closesocket(client->sock);
    client->sock = -1;
  }
}

int osdg_client_connect_to_server(osdg_client_t client, const struct osdg_endpoint *servers)
{
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

  free(list);

  for (i = 0; i < nServers; i++)
  {
    int res = osdg_client_try_to_connect(client, randomized[i]);

    if (res == 0)
    {
      /* Try to start the handshake */
      res = sendTELL(client);
      if (res == 0)
      {
        /* The server seems to be OK */
        void *buffer;

        free(randomized);

        buffer = client_get_buffer(client);
        res = blocking_loop(buffer, client);
        client_put_buffer(client, buffer);

        return res;
      }
      client_close_socket(client);
    }
  }

  free(randomized);
  client->errorKind = osdg_connection_failed;
  return -1;
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

