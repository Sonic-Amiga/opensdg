#ifdef _WIN32

#include <WinSock2.h>

static inline char *sock_errstr(void)
{
  char *str;

  FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                 NULL, WSAGetLastError(), LANG_USER_DEFAULT, (LPSTR)&str, 1, NULL);
  return str;
}

static inline void free_errstr(char *str)
{
  LocalFree(str);
}

#else

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>

static inline int closesocket(int s)
{
  return close(s);
}

static inline char *sock_errstr(void)
{
  return strerror(errno);
}

static inline void free_errstr(char *str)
{
  /* Nothing to do here */
}

#endif

