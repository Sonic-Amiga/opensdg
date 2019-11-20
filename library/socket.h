#ifndef INTERNAL_SOCKET_H
#define INTERNAL_SOCKET_H

#ifdef _WIN32

#include <WinSock2.h>

int sockerrno(void);

#else

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>

static inline int closesocket(int s)
{
  return close(s);
}

static inline int ioctlsocket(int s, unsigned long request, unsigned long *arg)
{
    return ioctl(s, request, arg);
}

static inline int sockerrno(void)
{
    return errno;
}

#endif

int connect_to_host(struct _osdg_connection *client, const char *host, unsigned short port);
int receive_data(struct _osdg_connection *client);
int send_data(const unsigned char *buffer, int size, struct _osdg_connection *client);

#endif
