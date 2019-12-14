/*
 * Could be a temporary solution, but anyways this is more than
 * the original Trifork library can handle
 */
#define MAX_CONNECTIONS 256

#include <sys/eventfd.h>
#include <poll.h>

#include "client.h"
#include "mainloop.h"
#include "socket.h"
#include "utils.h"

static struct _osdg_connection *connections[MAX_CONNECTIONS];
static unsigned int num_connections = 0;
static struct pollfd events[MAX_CONNECTIONS + 1];
static pthread_t thread;
static int stopFlag;

void mainloop_client_event(void)
{
    static const unsigned long long v = 1;

    write(events[0].fd, &v, sizeof(v));
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
    if (num_connections == MAX_CONNECTIONS)
    {
        conn->errorKind = osdg_too_many_connections;
        return -1;
    }

    connections[num_connections++] = conn;
    events[num_connections].fd = conn->sock;
    events[num_connections].events = POLLIN;

    return 0;
}

static void *osdg_main(void *arg)
{
    int timeout = -1;
    main_loop_start_cb();

    for (;;)
    {
        int r = poll(events, num_connections + 1, timeout);

        if (r > 0)
        {
            int i;

            for (i = 0; i <= num_connections; i++)
            {
                if (events[i].revents)
                {
                    if (i == 0)
                    {
                        unsigned long long buf;

                        /* Read the eventfd in order to reset it */
                        read(events[i].fd, &buf, sizeof(buf));
                        mainloop_handle_client_requests();

                        /* Ping interval for some connections could have been changed */
                        timeout = mainloop_ping(connections, num_connections);
                    }
                    else
                    {
                        connection_read_data(connections[i - 1]);
                    }
                    if (--r == 0)
                        break;
                }
            }

            /* Handling stopFlag after all pending client events should help
               to complete outstanting client requests like close connections */
            if (stopFlag)
                break;
        }
        else if (r == 0)
        {
            timeout = mainloop_ping(connections, num_connections);
        }
        else if (r == -1 && errno != EINTR && errno != EAGAIN)
        {
            return NULL; /* OS error code will be set */
        }
    }

    main_loop_stop_cb();
    return NULL;
}

int mainloop_init(void)
{
    int ret;

    events[0].fd = eventfd(0, 0);
    if (events[0].fd < 0)
        return -1;

    events[0].events = POLLIN;
    stopFlag = 0;
    
    ret = pthread_create(&thread, NULL, osdg_main, NULL);
    if (!ret)
        return 0;

    close(events[0].fd);
    errno = ret;
    return -1;
}

void mainloop_shutdown(void)
{
    stopFlag = 1;
    mainloop_client_event();
    pthread_join(thread, NULL);
    close(events[0].fd);
}
