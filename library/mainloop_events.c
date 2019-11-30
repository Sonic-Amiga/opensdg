#include "client.h"
#include "mainloop.h"
#include "utils.h"

static struct queue requests;

void mainloop_events_init(void)
{
    queue_init(&requests);
}

void mainloop_events_shutdown(void)
{
    queue_destroy(&requests);
}

void mainloop_send_client_request(struct client_req *req, client_req_cb_t function)
{
    req->function = function;
    queue_put(&requests, &req->qe);
    mainloop_client_event();
}

void mainloop_handle_client_requests(void)
{
    struct client_req *req;

    while (req = queue_get(&requests))
    {
        struct _osdg_connection *conn = (struct _osdg_connection *)req;
        int res = req->function(conn);

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