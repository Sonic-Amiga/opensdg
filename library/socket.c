#include "client.h"
#include "mainloop.h"
#include "socket.h"

#ifdef _WIN32

#include <WS2tcpip.h>

int sockerrno(void)
{
    int wsaErr = WSAGetLastError();

    switch (wsaErr)
    {
    case WSAEWOULDBLOCK:
        return EWOULDBLOCK;
    case WSAEINTR:
        return EINTR;
    case WSAEINPROGRESS:
        return EINPROGRESS;             
    case WSAENOTSOCK:
        return ENOTSOCK;
    case WSAEDESTADDRREQ:
        return EDESTADDRREQ;
    case WSAEMSGSIZE:
        return EMSGSIZE;
    case WSAEPROTOTYPE:
        return EPROTOTYPE;
    case WSAENOPROTOOPT:
        return ENOPROTOOPT;
    case WSAEPROTONOSUPPORT:
        return EPROTONOSUPPORT;
    case WSAEOPNOTSUPP:
        return EOPNOTSUPP;
    case WSAEAFNOSUPPORT:
        return EAFNOSUPPORT;
    case WSAEADDRINUSE:
        return EADDRINUSE;
    case WSAEADDRNOTAVAIL:
        return EADDRNOTAVAIL;
    case WSAENETDOWN:
        return ENETDOWN;
    case WSAENETUNREACH:
        return ENETUNREACH;
    case WSAENETRESET:
        return ENETRESET;
    case WSAECONNABORTED:
        return ECONNABORTED;
    case WSAECONNRESET:
        return ECONNRESET;
    case WSAENOBUFS:
        return ENOBUFS;
    case WSAEISCONN:
        return EISCONN;
    case WSAENOTCONN:
        return ENOTCONN;
    case WSAETIMEDOUT:
        return ETIMEDOUT;
    case WSAECONNREFUSED:
        return ECONNREFUSED;
    case WSAELOOP:
        return ELOOP;
    case WSAENAMETOOLONG:
        return ENAMETOOLONG;
    case WSAEHOSTUNREACH:
        return EHOSTUNREACH;
    case WSAENOTEMPTY:
        return ENOTEMPTY;
    default:
        return wsaErr;
    }
}

#else

#include <netdb.h>

#endif

static inline void set_socket_error(struct _osdg_connection *client)
{
    client->errorKind = osdg_socket_error;
    client->errorCode = sockerrno();
}

int connect_to_host(struct _osdg_connection *client, const char *host, unsigned short port)
{
    struct addrinfo *addr, *ai;
    int res;
    SOCKET s;

    res = getaddrinfo(host, NULL, NULL, &addr);
    if (res)
    {
        LOG(CONNECTION, "Failed to resolve %s: %s", host, gai_strerror(res));
        return 0;
    }

    for (ai = addr; ai; ai = ai->ai_next)
    {
        struct sockaddr *addr = ai->ai_addr;

        if (addr->sa_family == AF_INET)
        {
            ((struct sockaddr_in *)addr)->sin_port = htons(port);
        }
        else if (addr->sa_family == AF_INET6)
        {
            ((struct sockaddr_in6 *)addr)->sin6_port = htons(port);
        }
        else
        {
            LOG(CONNECTION, "Ignoring unknown address family %u for host %s", addr->sa_family, host);
            continue;
        }

        s = socket(addr->sa_family, SOCK_STREAM, 0);
        if (s == -1)
        {
            set_socket_error(client);
            LOG(ERRORS, "Failed to open socket for AF %d", addr->sa_family);
            res = -1;
            break;
        }

        res = connect(s, addr, (int)ai->ai_addrlen);
        if (!res)
        {
            static unsigned long nonblock = 1;
 
            LOG(CONNECTION, "Connected to %s:%u", host, port);
#ifndef _WIN32 /* TODO: Move to UNIX mainloop */
            res = ioctlsocket(s, FIONBIO, &nonblock);
            if (res)
            {
                set_socket_error(client);
                LOG(ERRORS, "Failed to set non-blocking mode");
                closesocket(s);
                break; /* It's a serious error, will return -1 */
            }
#endif
            client->sock = s;

            res = start_connection(client);
            if (!res)
            {
                mainloop_send_client_request(&client->req, mainloop_add_connection);
                res = 1; /* Connected */
                break;
            }

            /* This will also close the socket */
            connection_shutdown(client);
        }
        else
        {
            closesocket(s);
            LOG(CONNECTION, "Failed to connect to %s:%u", host, port);
            res = 0; 
        }
        res = 0; /* OK to try the next address */
    }

    freeaddrinfo(addr);
    return res;
}

int receive_data(struct _osdg_connection *client)
{
    while (client->bytesLeft)
    {
        int ret = recv(client->sock, &client->receiveBuffer[client->bytesReceived],
                       client->bytesLeft, 0);
        if (ret < 0)
        {
            int err = sockerrno();

            if (err == EWOULDBLOCK)
                return 0; /* Need more data */

            client->errorKind = osdg_socket_error;
            client->errorCode = err;
            return ret;
        }
        if (ret == 0)
        {
            LOG(ERRORS, "Connection[%p] closed by peer", client);
            client->errorKind = osdg_connection_closed;
            return -1;
        }

        client->bytesReceived += ret;
        client->bytesLeft -= ret;
    }

    return client->bytesReceived;
}

/* For simplicity this function is currently blocking */
osdg_result_t send_data(const unsigned char *buffer, int size, struct _osdg_connection *client)
{
    while (size)
    {
        int ret = send(client->sock, buffer, size, 0);

        if (ret < 0)
        {
            fd_set wfds;

            if (sockerrno() != EWOULDBLOCK)
                return osdg_socket_error;

            FD_ZERO(&wfds);
            FD_SET(client->sock, &wfds);

            ret = select((int)client->sock + 1, NULL, &wfds, NULL, NULL);
            if (ret < 0 && sockerrno() != EINTR)
                return osdg_socket_error;
        }
        else
        {
            size -= ret;
            buffer += ret;
        }
    }

    return osdg_no_error;
}
