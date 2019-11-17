/*
 * Could be a temporary solution, but anyways this is more than
 * the original Trifork library can handle
 */
#define MAX_CONNECTIONS 256

#include "client.h"
#include "mainloop.h"
#include "socket.h"

static struct _osdg_connection *connections[MAX_CONNECTIONS];
static DWORD num_connections = 0;
static WSAEVENT events[MAX_CONNECTIONS];

int mainloop_add_connection(struct _osdg_connection *conn)
{
    WSAEVENT e;

    if (num_connections == MAX_CONNECTIONS)
        return -1;

    e = WSACreateEvent();
    if (e == NULL)
    {
        conn->errorKind = osdg_socket_error;
        conn->errorCode = sockerrno();
        return -1;
    }

    /* This should not fail if WSACreateEvent() worked */
    WSAEventSelect(conn->sock, e, FD_READ|FD_CLOSE);

    events[num_connections] = e;
    connections[num_connections++] = conn;
    return 0;
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
    WSACloseEvent(events[i]);

    if (i != --num_connections)
    {
        /* An object is being deleted from the middle of our array.
           Replace it with the object from the end, for the sake of performance */
        connections[i] = connections[num_connections];
        events[i] = events[num_connections];
    }
}

int osdg_main(void)
{
    while (num_connections)
    {
        DWORD r = WSAWaitForMultipleEvents(num_connections, events, FALSE, WSA_INFINITE, FALSE);

        if (r >= WSA_WAIT_EVENT_0 && r < WSA_WAIT_EVENT_0 + num_connections)
        {
            int idx = r - WSA_WAIT_EVENT_0;

            /* WSA events do not auto-reset */
            WSAResetEvent(events[idx]);
            connection_read_data(connections[idx]);
        }
        else if (r == WSA_WAIT_FAILED)
        {
            return -1; /* OS error code will be set */
        }
    }

    return 0;
}
