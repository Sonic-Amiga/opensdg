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
