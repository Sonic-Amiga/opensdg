/*
 * Could be a temporary solution, but anyways this is more than
 * the original Trifork library can handle
 */
#define MAX_CONNECTIONS 256
#define FD_SETSIZE MAX_CONNECTIONS

#include "client.h"
#include "mainloop.h"

static struct _osdg_client *connections[MAX_CONNECTIONS];

int register_connection(struct _osdg_client *conn)
{
    int i;

    for (i = 0; i < MAX_CONNECTIONS; i++)
    {
        if (!connections[i])
        {
            connections[i] = conn;
            return 0;
        }
    }

    return -1;
}

void unregister_connection(struct _osdg_client *conn)
{
    int i;

    for (i = 0; i < MAX_CONNECTIONS; i++)
    {
        if (connections[i] == conn)
        {
            connections[i] = NULL;
            break;
        }
    }
}

/* We just don't want large arrays on stack */
static fd_set rset;

int osdg_main(void)
{
    for (;;)
    {
        int maxconn = 0;
        int maxfd = 0;
        int i, r;

        FD_ZERO(&rset);

        for (i = 0; i < MAX_CONNECTIONS; i++)
        {
            struct _osdg_client *conn = connections[i];

            if ((conn == NULL) || (conn->sock == -1))
                continue;

            /* This is terribly bad on Windows, but portable. Let's keep it for now. */
            FD_SET(conn->sock, &rset);

            maxconn = i + 1;
#ifndef _WIN32 /* maxfd is ignored on Windows */
            if (conn->sock > maxfd)
                maxfd = conn->sock;
#endif
        }

        if (maxconn == 0)
            return 0; /* Nothing left to do */

        r = select(maxfd + 1, &rset, NULL, NULL, NULL);
        if (r == -1)
            return -1; /* OS error code will be set */
        if (r == 0)
           continue; /* Shouldn't happen */

        for (i = 0; i < maxconn; i++)
        {
            struct _osdg_client *conn = connections[i];

            if ((conn == NULL) || (conn->sock == -1))
                continue;

            if (FD_ISSET(conn->sock, &rset))
            {
                connection_read_data(conn);
                if (--r == 0)
                    break;
            }
        }
    }
}
