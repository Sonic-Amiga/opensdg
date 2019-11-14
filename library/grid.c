#include "client.h"
#include "mainloop.h"
#include "socket.h"

int osdg_connect_to_grid(osdg_client_t client, const struct osdg_endpoint *servers)
{
    unsigned int nServers, left, i, res;
    const struct osdg_endpoint **list, **randomized;

    for (nServers = 0; servers[nServers].host; nServers++);
    if (nServers == 0)
    {
        client->errorKind = osdg_invalid_parameters;
        return -1;
    }

    res = connection_allocate_buffers(client);
    if (res)
        return res;

    /* Permute servers in random order in order to distribute the load */
    list = malloc(nServers * sizeof(void *));
    for (i = 0; i < nServers; i++)
        list[i] = &servers[i];

    randomized = malloc(nServers * sizeof(void *));
    left = nServers;
    for (i = 0; i < nServers; i++)
    {
        unsigned int idx = rand() / ((((unsigned int)RAND_MAX) + 1) / left);

        randomized[i] = list[idx];
        left--;
        list[idx] = list[left];
    }

    free((void *)list);

    for (i = 0; i < nServers; i++)
    {
        res = try_to_connect(client, randomized[i]->host, randomized[i]->port);

        if (res < 0)
            break; /* Serious error, give up now */
        if (res == 1)
        {
            register_connection(client);

            res = sendTELL(client);
            if (!res)
                break;

            connection_shutdown(client);
            res = -1;
        }
    }

    free((void *)randomized);

    if (res)
        client->errorKind = osdg_connection_failed;

    return res;
}

