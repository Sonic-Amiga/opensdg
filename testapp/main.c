#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <Winsock2.h>
#endif

#include "opensdg.h"
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

#else

static void printWSAError(const char *msg, int err)
{
  fprintf(stderr, "%s: %s\n", msg, strerror(err));
}

static inline int WSAGetLastError(void)
{
    return errno;
}

#endif

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

static int write_file(void *buffer, int size, const char *name)
{
    FILE *f = fopen(name, "wb");
    size_t res;

    if (!f)
        return -1;

    res = fwrite(buffer, size, 1, f);

    fclose(f);

    if (res == 1)
        return 0;

    printf("Failed to write file %s!\n", name);
    return -1;
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
  case osdg_memory_error:
    printf("Memory allocation error\n");
    break;
  case osdg_connection_refused:
    printf("Connection refused by peer\n");
    break;
  case osdg_too_many_connections:
    printf("Too many connections\n");
    break;
  case osdg_connection_closed:
    printf("Connection closed by peer\n");
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

static int lookup_peer(osdg_connection_t conn)
{
    unsigned int i;

    for (i = 0; i < num_peers; i++)
    {
        if (peers[i] == conn)
            return i;
    }

    return -1;
}

static void register_peer(unsigned int idx, osdg_connection_t peer)
{
    printf("Created connection #%u\n", idx);
    peers[idx] = peer;
    if (idx == num_peers)
        num_peers++;
}

static void print_status(osdg_connection_t conn, enum osdg_connection_state status)
{
    switch (status)
    {
    case osdg_closed:
        printf(" connection closed\n");
        break;
    case osdg_connected:
        printf(" connection established\n");
        break;
    case osdg_error:
        printf(" connection failed: ");
        print_client_error(conn);
        break;
    default:
        printf(" invalid status %u\n", status); /* You should not see this */
        break;
    }
}

static void grid_status_changed(osdg_connection_t conn, enum osdg_connection_state status)
{
    printf("Grid");
    print_status(conn, status);

    if (status == osdg_closed)
        osdg_connection_destroy(conn);
}

static void peer_status_changed(osdg_connection_t conn, enum osdg_connection_state status)
{
    int idx = lookup_peer(conn);

    printf("Peer #%d", idx);
    print_status(conn, status);

    if (status == osdg_closed)
    {
        peers[idx] = NULL;
        osdg_connection_destroy(conn);
    }
}

static void pairing_status_changed(osdg_connection_t conn, enum osdg_connection_state status)
{
    const unsigned char *peerId;

    switch (status)
    {
    case osdg_pairing_complete:
        peerId = osdg_get_peer_id(conn);
        printf("Pairing successful with peerId ");
        hexdump(peerId, sizeof(osdg_key_t));
        putchar('\n');
        break;
    case osdg_error:
        printf("Pairing failed: ");
        print_client_error(conn);
        break;
    default:
        printf("Invalid pairing status %u\n", status); /* You should not see this */
        break;
    }

    osdg_connection_destroy(conn);
}

static int default_peer_receive_data(osdg_connection_t conn, const unsigned char *data, unsigned int length)
{
    printf("Received data from the peer: ");
    dump_data(data, length);
    return 0;
}

static void connect_to_peer(osdg_connection_t client, char *argStr)
{
  unsigned int idx = get_peer_number();
  const char *arg;
  osdg_key_t peerId;
  osdg_connection_t peer;
  osdg_receive_cb_t receiveFunc;
  int res;

  if (idx == -1)
  {
    printf("Reached maximum number of connections\n");
    return;
  }

  arg = getWord(&argStr);
  if (strlen(arg) == 64)
  {
    size_t keyLen = 0;

    res = osdg_hex_to_bin(peerId, sizeof(peerId), arg, 64, NULL, &keyLen, NULL);
    if (res || (keyLen != sizeof(peerId)))
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

  osdg_set_state_change_callback(peer, peer_status_changed);

  if (!strcmp(arg, DEVISMART_PROTOCOL_NAME))
    receiveFunc = devismart_receive_data;
  else
    receiveFunc = default_peer_receive_data;

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

  register_peer(idx, peer);
}

static void pair_remote_peer(osdg_connection_t client, char *argStr)
{
  const char *otp = getWord(&argStr);
  osdg_connection_t peer;
  int res;

  peer = osdg_connection_create();
  if (!peer)
  {
      printf("Failed to create peer!\n");
      return;
  }

  osdg_set_state_change_callback(peer, pairing_status_changed);

  res = osdg_pair_remote(client, peer, otp);
  if (res)
  {
      printf("Failed to start connection!\n");
      osdg_connection_destroy(peer);
      return;
  }
}

static void close_connection(char *argStr)
{
    const char *arg = getWord(&argStr);
    char *end;
    unsigned int idx = strtoul(arg, &end, 10);

    if (arg == end || idx >= num_peers || peers[idx] == NULL)
    {
        printf("Invalid peer index %s!\n", arg);
        return;
    }

    osdg_connection_close(peers[idx]);
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

  /* This switches off DOS compatibility mode on Windows console */
  setlocale(LC_ALL, "");

  for (i = 1; i < argc; i++)
  {
      if (!strcmp(argv[i], "-l"))
      {
          logmask = atoi(argv[i + 1]);
          printf("Logging mask set to 0x%08X\n", logmask);
          i++;
      }
  }

  /* The only thing we can call before osdg_init() */
  osdg_set_log_mask(logmask);

  r = osdg_init();
  if (r)
  {
      printf("Failed to initialize OSDG!\n");
      return 255;
  }

  r = read_file(clientKey, sizeof(clientKey), "osdg_test_private_key.bin");
  if (!r)
  {
    printf("Loaded private key: ");
    dump_data(clientKey, sizeof(clientKey));
  }
  else
  {
      osdg_create_private_key(clientKey);
      printf("Generated private key: ");
      dump_data(clientKey, sizeof(clientKey));
      write_file(clientKey, sizeof(clientKey), "osdg_test_private_key.bin");
  }

  r = read_file(&pairings, sizeof(pairings), "osdg_test_pairings.bin");
  if (r)
    pairings.count = 0;

  osdg_set_private_key(clientKey);

  client = osdg_connection_create();
  if (!client)
  {
    printf("Failed to create client!\n");
    return 255;
  }

  osdg_set_state_change_callback(client, grid_status_changed);

  r = osdg_connect_to_grid(client, servers);
  if (r == 0)
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
        else if (!strcmp(cmd, "pair"))
        {
            pair_remote_peer(client, p);
        }
        else if (!strcmp(cmd, "close"))
        {
            close_connection(p);
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
    print_client_error(client);
  }

  osdg_connection_close(client);

  osdg_shutdown();
  return 0;
}
