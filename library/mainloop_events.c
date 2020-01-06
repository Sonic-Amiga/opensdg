#include "client.h"
#include "mainloop.h"
#include "utils.h"

const struct osdg_main_loop_callbacks *main_cb = NULL;

void osdg_set_mainloop_callbacks(const struct osdg_main_loop_callbacks *cb)
{
    main_cb = cb;
}

struct queue mainloop_requests;

void mainloop_events_init(void)
{
    queue_init(&mainloop_requests);
}

void mainloop_events_shutdown(void)
{
    queue_destroy(&mainloop_requests);
}

void mainloop_send_client_request(struct client_req *req, client_req_cb_t function)
{
    client_req_cb_t oldCb;

    pthread_mutex_lock(&mainloop_requests.lock);

    /* oldCb will tell us if we are re-sending the request or not. If it is non-NULL,
     * the callback has already been assigned and the request is already in the queue
     * but not processed yet. In this case we don't need to reinsert our request into
     * the queue (which would screw it up) and send one more event.
     * Aborting and re-sending a request can happen during osdg_connection_close()
     * right after e.g. osdg_connect_to_remote(). In this case we will abort the
     * connection process and jump right to close procedure.
     */
    oldCb = req->function;
    req->function = function;

    if (oldCb == NULL)
        queue_put_nolock(&mainloop_requests, &req->qe);

    pthread_mutex_unlock(&mainloop_requests.lock);

    if (oldCb == NULL)
        mainloop_client_event();
}

struct _osdg_connection *mainloop_get_client_request(client_req_cb_t *function)
{
    struct _osdg_connection *conn;

    pthread_mutex_lock(&mainloop_requests.lock);

    conn = (struct _osdg_connection *)queue_get_nolock(&mainloop_requests);
    if (conn) {
        *function = conn->req.function;
        conn->req.function = NULL;
    }

    pthread_mutex_unlock(&mainloop_requests.lock);
    return conn;
}

void mainloop_handle_client_requests(void)
{
    struct _osdg_connection *conn;
    client_req_cb_t function;

    while (conn = mainloop_get_client_request(&function))
    {
        int res = function(conn);

        if (res)
            connection_terminate(conn, osdg_error);
    }
}

int mainloop_ping(struct _osdg_connection **connList, unsigned int connCount)
{
    unsigned int i;
    unsigned long long sleepUntil = -1LL;
    unsigned long long now;

    for (i = 0; i < connCount; i++)
    {
        struct _osdg_connection *conn = connList[i];
        unsigned long long nextPing;

        if (conn->mode != mode_grid || conn->state != osdg_connected)
            continue;

        if (timestamp() - conn->lastPing >= conn->pingInterval)
        {
            osdg_result_t r = connection_ping(conn);

            if (r != osdg_no_error)
            {
                connection_set_result(conn, r);
                connection_terminate(conn, osdg_error);
                /* connection_terminate() modifies connections array.
                 * The main loop will refresh itself and call us again */
                return 0;
            }
        }

        nextPing = conn->lastPing + conn->pingInterval;
        if (nextPing < sleepUntil)
            sleepUntil = nextPing;
    }

    if (sleepUntil == -1LL)
        return -1;

    now = timestamp();
    return now > sleepUntil ? (int)(now - sleepUntil) : 0;
}