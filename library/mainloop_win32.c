/*
 * Could be a temporary solution, but anyways this is more than
 * the original Trifork library can handle
 */
#define MAX_CONNECTIONS 256

#include "client.h"
#include "mainloop.h"
#include "socket.h"
#include "utils.h"

static struct _osdg_connection *connections[MAX_CONNECTIONS];
static DWORD num_connections = 0;
static WSAEVENT events[MAX_CONNECTIONS + 1];

int mainloop_init(void)
{
    WSAEVENT e = WSACreateEvent();

    if (!e)
        return -1;

    events[0] = e;
    return 0;
}

void mainloop_shutdown(void)
{
    WSACloseEvent(events[0]);
}

void mainloop_client_event(void)
{
    WSASetEvent(events[0]);
}

void mainloop_remove_connection(struct _osdg_connection *conn)
{
    unsigned int i;

    for (i = 0; i < num_connections; i++)
    {
        if (connections[i] == conn)
            break;
    }

    if (i == num_connections)
        return;

    WSAEventSelect(conn->sock, events[i], 0);
    WSACloseEvent(events[i + 1]);

    if (i != --num_connections)
    {
        /* An object is being deleted from the middle of our array.
           Replace it with the object from the end, for the sake of performance */
        connections[i] = connections[num_connections];
        events[i + 1] = events[num_connections + 1];
    }
}

int mainloop_add_connection(struct _osdg_connection *conn)
{
    WSAEVENT e;

    if (num_connections == MAX_CONNECTIONS)
    {
        conn->errorKind = osdg_too_many_connections;
        return -1;
    }

    e = WSACreateEvent();
    if (e == NULL)
    {
        conn->errorKind = osdg_socket_error;
        conn->errorCode = sockerrno();
        return -1;
    }

    /* This should not fail if WSACreateEvent() worked */
    WSAEventSelect(conn->sock, e, FD_READ | FD_CLOSE);

    connections[num_connections++] = conn;
    events[num_connections] = e;

    return 0;
}

int osdg_main(void)
{
    for (;;)
    {
        DWORD r = WSAWaitForMultipleEvents(num_connections + 1, events, FALSE, WSA_INFINITE, FALSE);

        if (r == WSA_WAIT_EVENT_0)
        {
            WSAResetEvent(events[0]);
            mainloop_handle_client_requests();
        }
        else if (r > WSA_WAIT_EVENT_0 && r <= WSA_WAIT_EVENT_0 + num_connections)
        {
            int idx = r - WSA_WAIT_EVENT_0;

            /* WSA events do not auto-reset */
            WSAResetEvent(events[idx]);
            connection_read_data(connections[idx - 1]);
        }
        else if (r == WSA_WAIT_FAILED)
        {
            return -1; /* OS error code will be set */
        }
    }

    return 0;
}
