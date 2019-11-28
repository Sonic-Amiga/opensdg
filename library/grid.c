#include "client.h"
#include "control_protocol.h"
#include "mainloop.h"
#include "socket.h"

static int grid_handle_incoming_packet(struct _osdg_connection *conn,
                                       const unsigned char *data, unsigned int length)
{
    int ret = -1;
    unsigned char msgType;
  
    /*
     * Grid messages come in protobuf format, prefixed by one byte, indicating
     * message type.
     */
    if (length == 0)
    {
        LOG(ERRORS, "Empty grid packet received");
        return 0; /* Ignore this */
    }

    msgType = *data++;
    length--;

    if (msgType == MSG_PROTOCOL_VERSION)
    {
        ProtocolVersion *protocolVer = protocol_version__unpack(NULL, length, data);

        if (!protocolVer)
        {
            LOG(ERRORS, "MSG_PROTOCOL_VERSION protobuf decoding error");
            return -1;
        }

        if (protocolVer->magic != PROTOCOL_VERSION_MAGIC)
        {
            LOG(ERRORS, "Incorrect protocol version magic 0x%08X", protocolVer->magic);
        } else if (protocolVer->major != PROTOCOL_VERSION_MAJOR || protocolVer->minor != PROTOCOL_VERSION_MINOR)
        {
            LOG(ERRORS, "Unsupported grid protocol version %u.%u", protocolVer->major, protocolVer->minor);
        } else
        {
            LOG(PROTOCOL, "Using protocol version %u.%u", protocolVer->major, protocolVer->minor);
            ret = 0; /* We're done with the handshake */
        }

        protocol_version__free_unpacked(protocolVer, NULL);

        if (!ret)
            connection_set_status(conn, osdg_connected);

    } else if (msgType = MSG_REMOTE_REPLY)
    {
        PeerReply *reply = peer_reply__unpack(NULL, length, data);
        struct list_element *req;

        if (!reply)
        {
            DUMP(ERRORS, data, length, "MSG_REMOTE_REPLY protobuf decoding error");
            return 0; /* Do not abort grid connection */
        }

        for (req = conn->forwardList.head; req->next; req = req->next)
        {
            struct _osdg_connection *peer = get_connection(req);

            if (peer->uid == reply->id)
            {
                list_remove(req);
                ret = peer_handle_remote_call_reply(peer, reply);
                peer_reply__free_unpacked(reply, NULL);
                return ret;
            }
        }

        LOG(ERRORS, "Received MSG_PEER_REPLY for nonexistent peer %u\n", reply->id);
        peer_reply__free_unpacked(reply, NULL);
        return 0; /* Ignore, this is not critical */
    }
    else if (msgType == MSG_INCOMING_CALL)
    {
        IncomingCall *call = incoming_call__unpack(NULL, length, data);
        IncomingCallReply reply = INCOMING_CALL_REPLY__INIT;

        if (!call)
        {
            DUMP(ERRORS, data, length, "MSG_INCOMING_CALL protobuf decoding error");
            return 0; /* Do not abort grid connection */
        }

        LOG(PROTOCOL, "Incoming call from %s protocol %s", call->peer->peerid, call->protocol);

        /* We are client only; reject */
        reply.id = call->id;
        reply.result = 0;

        incoming_call__free_unpacked(call, NULL);
        ret = sendMESG(conn, MSG_INCOMING_CALL_REPLY, &reply);
    }
    else
    {
        DUMP(PROTOCOL, data, length, "Unhandled grid message type %u", msgType);
        return 0;
    }

    return ret;
}

osdg_result_t osdg_connect_to_grid(osdg_connection_t client, const struct osdg_endpoint *servers)
{
    unsigned int nServers, left, i, res;
    const struct osdg_endpoint **list, **randomized;

    if (connection_in_use(client))
        return osdg_connection_busy;

    for (nServers = 0; servers[nServers].host; nServers++);
    if (nServers == 0)
    {
        client->errorKind = osdg_invalid_parameters;
        return osdg_invalid_parameters;
    }

    res = connection_allocate_buffers(client);
    if (res)
        return client->errorKind;

    client->mode              = mode_grid;
    client->state             = osdg_connecting;
    client->receiveData       = grid_handle_incoming_packet;
    client->discardFirstBytes = 0;

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
        res = connect_to_host(client, randomized[i]->host, randomized[i]->port);
        if (res != 0)
            break; /* Success or serious error */
    }

    free((void *)randomized);

    if (res < 0)
    {
        client->errorKind = osdg_connection_failed;
        return osdg_connection_failed;
    }

    return osdg_no_error;
}
