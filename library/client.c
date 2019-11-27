#include <sodium.h>
#include <string.h>

#include "client.h"
#include "logging.h"
#include "mainloop.h"
#include "socket.h"

/* Our key pair */
unsigned char clientPubkey[crypto_box_PUBLICKEYBYTES];
unsigned char clientSecret[crypto_box_SECRETKEYBYTES];

void osdg_set_private_key(const osdg_key_t private_key)
{
    memcpy(clientSecret, private_key, sizeof(clientSecret));
    /* Compute the public key */
    crypto_scalarmult_base(clientPubkey, clientSecret);
}

unsigned char *osdg_get_my_peer_id(void)
{
  return clientPubkey;
}

static inline void client_put_buffer_nolock(struct _osdg_connection *client, struct osdg_buffer *buffer)
{
    queue_put_nolock(&client->bufferQueue, &buffer->qe);
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
  client->sock          = -1;
  client->errorKind     = osdg_no_error;
  client->errorCode     = 0;
  client->mode          = mode_none;
  client->state         = osdg_closed;
  client->changeState   = NULL;
  client->receiveData   = NULL;
  client->nonce         = 0;
  client->tunnelId      = NULL;
  client->haveBuffers   = 0;
  /*
   * This buffer size is used by original mdglib from DEVISmart Android APK,
   * so we're using it as a default.
   */
  client->bufferSize    = 1536;
  client->receiveBuffer = NULL;

  queue_init(&client->bufferQueue);

  return client;
}

void connection_shutdown(struct _osdg_connection *client)
{
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

void connection_terminate(struct _osdg_connection *conn, enum osdg_connection_state state)
{
    struct list_element *req, *next;

    mainloop_remove_connection(conn);
    connection_shutdown(conn);

    /* Terminate also peers, waiting for forwarding reply */
    for (req = conn->forwardList.head; req->next; req = next)
    {
        struct _osdg_connection *peer = get_connection(req);

        /* User's callback can even destroy the connection, so remember next pointer early */
        next = req->next;

        if (state == osdg_error)
        {
            peer->errorKind = conn->errorKind;
            peer->errorCode = conn->errorCode;
        }

        connection_terminate(peer, state);
    }

    list_init(&conn->forwardList);
    connection_set_status(conn, state);
}

int osdg_connection_close(osdg_connection_t client)
{
    /* In this state another request can be in progress;
       adding client->req to main loop's queue for the second time will screw it up
       CHECKME: Will it be comfortable or not ? */
    if (client->state == osdg_connecting)
      return -1;

    client->req.code = REQUEST_CLOSE;
    mainloop_send_client_request(&client->req);

    /* TODO: Check for dumb things like double close */
    return 0;
}

void osdg_connection_destroy(osdg_connection_t client)
{
  struct queue_element *buffer, *next;

  for (buffer = client->bufferQueue.head; buffer; buffer = next)
  {
    next = buffer->next;
    free(buffer);
  }

  queue_destroy(&client->bufferQueue);
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

enum osdg_connection_state osdg_get_connection_state(osdg_connection_t conn)
{
    return conn->state;
}

int osdg_set_state_change_callback(osdg_connection_t client, osdg_state_cb_t f)
{
    client->changeState = f;
    return 0;
}

int osdg_set_receive_data_callback(osdg_connection_t client, osdg_receive_cb_t f)
{
    /* Grid connections have internal data handler, don't screw them up */
    if (connection_in_use(client) && client->mode != mode_peer)
        return -1;

    client->receiveData = f;
    return 0;
}

void *client_get_buffer(struct _osdg_connection *client)
{
  struct osdg_buffer *buffer = queue_get(&client->bufferQueue);

  if (!buffer)
    buffer = malloc(client->bufferSize);

  return buffer;
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
        connection_terminate(conn, osdg_error);
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
