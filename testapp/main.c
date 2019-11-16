#include <ctype.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <Winsock2.h>
#endif

#include "opensdg.h"
#include "pthread_wrapper.h"
#include "testapp.h"
#include "devismart.h"
#include "devismart_protocol.h"

#define MAX_PEERS 32

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

static int hexchar2bin(char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  else if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  else if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  else
    return -1;
}

static int hex2bin(unsigned char *bin, unsigned int len, const char *hex)
{
  unsigned int i, j;

  for (i = 0; i < len; i++)
  {
    int digit[2];

    for (j = 0; j < 2; j++)
    {
      digit[j] = hexchar2bin(hex[i * 2 + j]);
      if (digit[j] == -1)
        return -1;
    }

    bin[i] = (digit[0] << 4) + digit[1];
  }

  return hex[len * 2] ? -1 : 0;
}

static int read_file(void *buffer, int size, const char *name)
{
    FILE *f = fopen(name, "rb");
    size_t res;

    if (!f)
      return -1;

    res = fread(buffer, size, 1, f);

    fclose(f);
    return res == 1 ? 0 : -1;
}

static void print_client_error(osdg_connection_t client)
{
  enum osdg_error_kind kind = osdg_get_error_kind(client);

  switch (kind)
  {
  case osdg_socket_error:
    printWSAError("Socket I/O error", osdg_get_error_code(client));
    break;
  case osdg_encryption_error:
    printf("Libsodium encryption error\n");
    break;
  case osdg_decryption_error:
    printf("Libsodium decryption error\n");
    break;
  case osdg_protocol_error:
    printf("Unrecoverable protocol error\n");
    break;
  case osdg_buffer_exceeded:
    printf("Buffer overrun\n");
    break;
  case osdg_invalid_parameters:
    printf("Invalid function call parameters\n");
    break;
  case osdg_connection_failed:
    printf("Failed to connect to host\n");
    /* Probably not legitimate, but good for internal diagnostics */
    printWSAError("Last socket error", osdg_get_error_code(client));
    break;
  default:
    printf("Unknon error kind %d\n", kind);
    break;
  }
}

const char *getWord(char **p)
{
  char *buffer = *p;
  char *end;

  for (end = buffer; *end; end++)
  {
    if (isspace(*end))
    {
      *end++ = 0;
      while (isspace(*end))
        end++;
      break;
    }
  }
  *p = end;
  return buffer;
}

void hexdump(const unsigned char *data, unsigned int size)
{
  unsigned int i;

  for (i = 0; i < size; i++)
    printf("%02x", data[i]);
}

static pthread_t inputThread;

static void *input_loop(void *arg)
{
  int ret = osdg_main();

  if (ret)
    printf("Main loop exited with an error\n");
  else
    printf("Main loop exited normally\n");

  return NULL;
}

struct pairing_data
{
  osdg_key_t peerId;
  char       description[256];
};

struct pairing_list
{
  unsigned int        count;
  struct pairing_data data[MAX_PEERS];
};

static struct pairing_list pairings;

static void list_pairings(void)
{
  unsigned int i;

  for (i = 0; i < pairings.count; i++)
  {
    printf("%2d ", i);
    hexdump(pairings.data[i].peerId, sizeof(osdg_key_t));
    printf(" %s\n", pairings.data[i].description);
  }
}

static osdg_connection_t peers[MAX_PEERS];
static unsigned int num_peers = 0;

static int get_peer_number(void)
{
  unsigned int i;

  for (i = 0; i < num_peers; i++)
  {
    if (!peers[i])
      return i;
  }

  return (num_peers == MAX_PEERS) ? -1 : num_peers;
}

static void list_peers(void)
{
  unsigned int i;

  for (i = 0; i < num_peers; i++)
  {
    if (!peers[i])
      continue;

    printf("%2d ", i);
    hexdump(osdg_get_peer_id(peers[i]), sizeof(osdg_key_t));
    putchar('\n');
  }
}

static void connect_to_peer(osdg_connection_t client, char *argStr)
{
  unsigned int idx = get_peer_number();
  const char *arg;
  osdg_key_t peerId;
  osdg_connection_t peer;
  int res;

  if (idx == -1)
  {
    printf("Reached maximum number of connections\n");
    return;
  }

  arg = getWord(&argStr);
  if (strlen(arg) == 64)
  {
    if (hex2bin(peerId, sizeof(peerId), arg) != 0)
    {
      printf("Invalid peerID %s!\n", arg);
      return;
    }
  }
  else
  {
    char *end;
    unsigned int idx = strtoul(arg, &end, 10);

    if (arg == end || idx >= pairings.count)
    {
      printf("Invalid peer index %s!\n", arg);
      return;
    }

    memcpy(peerId, pairings.data[idx].peerId, sizeof(osdg_key_t));
  }

  arg = getWord(&argStr);
  if (!arg[0])
    arg = DEVISMART_PROTOCOL_NAME; // Default to DEVISmart thermostat protocol

  peer = osdg_connection_create();
  if (!peer)
  {
    printf("Failed to create peer!\n");
    return;
  }

  res = osdg_set_receive_data_callback(peer, devismart_receive_data);
  if (res)
  {
      printf("Failed to set data receive callback!\n");
      osdg_connection_destroy(peer);
      return;
  }

  res = osdg_connect_to_remote(client, peer, peerId, arg);
  if (res)
  {
    printf("Failed to start connection!\n");
    osdg_connection_destroy(peer);
    return;
  }

  printf("Created connection #%u\n", idx);
  peers[idx] = peer;
  if (idx == num_peers)
    num_peers++;
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

int main(int argc, const char *const *argv)
{
  unsigned int logmask = OSDG_LOG_ERRORS;
  osdg_key_t clientKey;
  osdg_connection_t client;
  int i, r;

  for (i = 1; i < argc; i++)
  {
      if (!strcmp(argv[i], "-l"))
      {
          logmask = atoi(argv[i + 1]);
          printf("Logging mask set to 0x%08X\n", logmask);
          i++;
      }
  }

  osdg_set_log_mask(logmask);

  /* This switches off DOS compatibility mode on Windows console */
  setlocale(LC_ALL, "");
  initSockets();

  r = read_file(clientKey, sizeof(clientKey), "osdg_test_private_key.bin");
  if (r)
  {
      /* TODO: Generate and save the key */
      printf("Failed to load private key! Leaving uninitialized!\n");
  }

  r = read_file(&pairings, sizeof(pairings), "osdg_test_pairings.bin");
  if (r)
    pairings.count = 0;

  if (osdg_init(clientKey))
  {
      printf("osdg_init() failed!\n");
      return 255;
  }

  client = osdg_connection_create();
  if (!client)
  {
    printf("Failed to create client!\n");
    return 255;
  }

  r = osdg_connect_to_grid(client, servers);
  if (r == 0)
  {
    printf("Connection request sent, starting main loop\n");

    r = pthread_create(&inputThread, NULL, input_loop, client);
    if (!r)
    {
      printf("Enter command; \"help\" to get help\n");

      for (;;)
      {
        char buffer[256];
        char *p = buffer;
        const char *cmd;

        putchar('>');
        fgets(buffer, sizeof(buffer), stdin);

        cmd = getWord(&p);

        if (!cmd[0])
          continue;

        if (!strcmp(cmd, "help"))
        {
          printf("help                   - this help\n"
                 "connect [peer # or ID] - connect to peer by index or raw ID\n"
                 "list pairings          - list known pairings\n"
                 "list peers             - list current connections\n"
                 "quit                   - end session\n");
        }
        else if (!strcmp(cmd, "connect"))
        {
          connect_to_peer(client, p);
        }
        else if (!strcmp(cmd, "list"))
        {
          cmd = getWord(&p);
          if (!strcmp(cmd, "pairings"))
            list_pairings();
          else if (!strcmp(cmd, "peers"))
            list_peers();
          else
            printf("Unknown item %s", cmd);
        }
        else if (!strcmp(cmd, "quit"))
        {
          break;
        }
        else
        {
          printf("Unknown command %s\n", cmd);
        }
      }
    }
    else
    {
      printf("Failed to start input thread!\n");
    }
  }
  else
  {
    print_client_error(client);
  }

  osdg_connection_destroy(client);
  WSACleanup();

  return 0;
}
