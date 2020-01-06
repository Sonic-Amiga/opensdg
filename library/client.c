#include <sodium.h>
#include <string.h>
#include <time.h>

#include "client.h"
#include "logging.h"
#include "mainloop.h"
#include "socket.h"

void osdg_set_private_key(osdg_connection_t conn, const osdg_key_t private_key)
{
    memcpy(conn->clientSecret, private_key, sizeof(conn->clientSecret));
    /* Compute the public key */
    crypto_scalarmult_base(conn->clientPubkey, conn->clientSecret);
}

unsigned char *osdg_get_my_peer_id(osdg_connection_t conn)
{
  return conn->clientPubkey;
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

  client->req.function  = NULL;
  client->uid           = -1;
  client->sock          = -1;
  client->errorKind     = osdg_no_error;
  client->errorCode     = 0;
  client->mode          = mode_none;
  client->state         = osdg_closed;
  client->changeState   = NULL;
  client->receiveData   = NULL;
  client->userData      = NULL;
  client->nonce         = 0;
  client->tunnelId      = NULL;
  client->blocking      = 0;
  client->closing       = 0;
  client->haveBuffers   = 0;
  /*
   * This buffer size is used by original mdglib from DEVISmart Android APK,
   * so we're using it as a default.
   */
  client->bufferSize    = 1536;
  client->receiveBuffer = NULL;
  client->pingInterval  = 0;

  list_init(&client->forwardList);
  queue_init(&client->bufferQueue);
  event_init(&client->completion);

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

static int connection_close(struct _osdg_connection *conn)
{
    conn->closing = 0;
    connection_terminate(conn, osdg_closed);
    return 0;
}

osdg_result_t osdg_connection_close(osdg_connection_t conn)
{
    /* We specify "closing" state as completely separate flag in order to avoid race
       with main thread, which could have errored out at the very same moment and
       would be setting "error" state */
    if (conn->closing)
      return osdg_wrong_state;

    conn->closing  = 1;
    mainloop_send_client_request(&conn->req, connection_close);
    return connection_wait(conn);
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
  event_destroy(&client->completion);
  free(client);
}

osdg_result_t osdg_get_last_result(osdg_connection_t client)
{
  return client->errorKind;
}

int osdg_get_last_errno(osdg_connection_t client)
{
  return client->errorCode;
}

size_t osdg_get_last_result_str(osdg_connection_t conn, char *buffer, size_t len)
{
    const char *res = osdg_get_result_str(conn->errorKind);
    size_t rl = strlen(res) + 1;

    if (conn->errorKind == osdg_socket_error)
    {
        const char *err = strerror(conn->errorCode);

        rl += strlen(err) + 2;

        if (buffer)
            snprintf(buffer, len, "%s: %s", res, err);
    }
    else if (buffer)
        strncpy(buffer, res, len);

    return rl;
}

const unsigned char *osdg_get_peer_id(osdg_connection_t conn)
{
    return conn->serverPubkey;
}

enum osdg_connection_state osdg_get_connection_state(osdg_connection_t conn)
{
    return conn->state;
}

osdg_result_t osdg_set_state_change_callback(osdg_connection_t client, osdg_state_cb_t f)
{
    client->changeState = f;
    return osdg_no_error;
}

osdg_result_t osdg_set_receive_data_callback(osdg_connection_t client, osdg_receive_cb_t f)
{
    /* Grid and pairing connections have internal data handler, don't screw them up */
    if (connection_in_use(client) && client->mode != mode_peer)
        return osdg_wrong_state;

    client->receiveData = f;
    return osdg_no_error;
}

void osdg_set_user_data(osdg_connection_t conn, void *data)
{
    conn->userData = data;
}

void *osdg_get_user_data(osdg_connection_t conn)
{
    return conn->userData;
}

void osdg_set_blocking_mode(osdg_connection_t conn, int blocking)
{
    conn->blocking = blocking;
}

int osdg_get_blocking_mode(osdg_connection_t conn)
{
    return conn->blocking;
}

void connection_set_status(struct _osdg_connection *conn, enum osdg_connection_state state)
{
    enum osdg_connection_state oldState = conn->state;
    /* For non-blocking connection state change callback can destroy the connection
       if it won't be used any more, so read blocking flag right now. */
    int blocking = conn->blocking;

    conn->state = state;
    if (conn->changeState)
        conn->changeState(conn, state);
    if (!blocking)
        return;
    if (oldState == osdg_connecting || state == osdg_closed || state == osdg_pairing_complete)
        event_post(&conn->completion);
}

osdg_result_t connection_wait(struct _osdg_connection *conn)
{
    if (conn->blocking)
    {
        event_wait(&conn->completion);
        if (conn->state == osdg_error)
            return conn->errorKind;
    }

    return osdg_no_error;
}

int connection_set_result(struct _osdg_connection *conn, osdg_result_t result)
{
    if (result == osdg_no_error)
        return 0;
    if (result == osdg_socket_error)
        conn->errorCode = sockerrno();
    conn->errorKind = result;
    return -1;
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
