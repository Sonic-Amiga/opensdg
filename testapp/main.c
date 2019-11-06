#include <locale.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "opensdg.h"

#ifdef _WIN32

static void printWSAError(const char *msg, int err)
{
    char *str;

    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err, LANG_USER_DEFAULT, (LPSTR)&str, 1, NULL);
    fprintf(stderr, "%s: %s\n", msg, str);
    LocalFree(str);
}

static void printsockerr(const char *msg)
{
  printWSAError(msg, WSAGetLastError());
}

static void initSockets(void)
{
  WSADATA wsData;
  int err = WSAStartup(MAKEWORD(2, 2), &wsData);

  if (err)
  {
    printWSAError("Failed to initialize winsock", err);
    exit(255);
  }
}

#else

static void printWSAError(const char *msg, int err)
{
  fprintf(stderr, "%s: %s\n", msg, strerror(err));
}

static inline void printsockerr(const char *msg)
{
  perror(msg);
}

static inline int closesocket(int s)
{
  return close(s);
}

static inline void initSockets(void)
{
}

static inline void WSACleanup(void)
{
}

#endif

int read_file(unsigned char *buffer, int size, const char *name)
{
    FILE *f = fopen(name, "rb");

    if (!f)
      return -1;

    if (fread(buffer, size, 1, f) != 1)
      return -1;

    fclose(f);
    return 0;
}

int main()
{
  SOCKET s;
  struct sockaddr_in sa;
  osdg_key_t clientKey;
  osdg_client_t client;
  int r;

  /* This switches off DOS compatibility mode on Windows console */
  setlocale(LC_ALL, "");
  initSockets();

  r = read_file(clientKey, sizeof(clientKey), "osdg_test_private_key.bin");
  if (r)
  {
      /* TODO: Generate and save the key */
      printf("Failed to load private key! Leaving uninitialized!\n");
  }

  client = osdg_client_create(clientKey);
  if (!client)
  {
    printf("Failed to create client!\n");
    return 255;
  }

  s = socket(PF_INET, SOCK_STREAM, 0);
  if (s < 0)
  {
    printsockerr("Failed to create socket");
    return 255;
  }
	
  sa.sin_family = AF_INET;
  sa.sin_port = htons(443);
  inet_pton(AF_INET, "77.66.11.90", &sa.sin_addr);
	
  r = connect(s, (struct sockaddr *)&sa, sizeof(sa));
  if (r < 0)
  {
    printsockerr("Failed to connect");
    closesocket(s);
    return 255;
  }

  r = osdg_client_connect_to_socket(client, s);
  if (r == 0)
  {
      printf("Done\n");
  }
  else
  {
      enum osdg_error_kind kind = osdg_client_get_error_kind(client);
      int code = osdg_client_get_error_code(client);

      switch (kind)
      {
      case osdg_socket_error:
        printWSAError("Socket I/O error", code);
        break;
      case osdg_sodium_error:
        printf("Libsodium error code %d\n", code);
        break;
      default:
        printf("Unknon error kind %d code %d\n", kind, code);
        break;
      }
  }

  closesocket(s);
  WSACleanup();
  osdg_client_destroy(client);
  return 0;
}
