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

void mainloop_send_client_request(struct client_req *req)
{
    queue_put(&requests, &req->qe);
    mainloop_client_event();
}

void mainloop_handle_client_requests(void)
{
    struct client_req *req;

    while (req = queue_get(&requests))
    {
        struct _osdg_connection *conn = (struct _osdg_connection *)req;
        int res = 0;

        switch (req->code)
        {
        case REQUEST_ADD:
            res = mainloop_add_connection(conn);
            break;
        case REQUEST_CLOSE:
            conn->closing = 0;
            connection_terminate(conn, osdg_closed);
            break;
        case REQUEST_CALL_REMOTE:
            res = peer_call_remote(conn);
            break;
        case REQUEST_PAIR_REMOTE:
            res = peer_pair_remote(conn);
            break;
        }

        if (res)
            connection_terminate(conn, osdg_error);
    }
}
