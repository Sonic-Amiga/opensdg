#include <locale.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <ws2tcpip.h>
#else
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

/* Danfoss cloud servers */
static const struct osdg_endpoint servers[] =
{
  {"77.66.11.90" , 443},
  {"77.66.11.92" , 443},
  {"5.179.92.180", 443},
  {"5.179.92.182", 443},
  {NULL, 0}
};

int main()
{
  SOCKET s;
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

  client = osdg_client_create(clientKey, 1536);
  if (!client)
  {
    printf("Failed to create client!\n");
    return 255;
  }

  r = osdg_client_connect_to_server(client, servers);
  if (r == 0)
  {
      printf("Done\n");
  }
  else
  {
      enum osdg_error_kind kind = osdg_client_get_error_kind(client);

      switch (kind)
      {
      case osdg_socket_error:
        printWSAError("Socket I/O error", osdg_client_get_error_code(client));
        break;
      case osdg_encryption_error:
        printf("Libsodium encryption error\n");
        break;
      case osdg_decryption_error:
        printf("Libsodium decryption error\n");
        break;
      default:
        printf("Unknon error kind %d\n", kind);
        break;
      }
  }

  WSACleanup();
  osdg_client_destroy(client);
  return 0;
}
