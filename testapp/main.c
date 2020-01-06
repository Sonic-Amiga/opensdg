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

void print_result(osdg_result_t res)
{
    printf("%s\n", osdg_get_result_str(res));
}

void print_client_error(osdg_connection_t client)
{
  char buffer[1024];

  osdg_get_last_result_str(client, buffer, sizeof(buffer));
  printf("%s\n", buffer);
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

int add_pairing(osdg_key_t peerId, const char *description)
{
  unsigned int i;
  
  for (i = 0; i < pairings.count; i++)
  {
    if (!memcmp(pairings.data[i].peerId, peerId, sizeof(osdg_key_t)))
      return 0;
  }

  if (pairings.count == MAX_PEERS - 1)
  {
    printf("Cannot add more peers!\n");
    return -1;
  }

  i = pairings.count++;
  memcpy(pairings.data[i].peerId, peerId, sizeof(osdg_key_t));
  strcpy(pairings.data[i].description, description);

  return 0;
}

int save_pairings(void)
{
  return write_file(&pairings, sizeof(pairings), "osdg_test_pairings.bin");
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

void print_status(osdg_connection_t conn, enum osdg_connection_state status)
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
}

static void peer_status_changed(osdg_connection_t conn, enum osdg_connection_state status)
{
    int idx = lookup_peer(conn);

    printf("Peer #%d", idx);
    print_status(conn, status);

    if ((!osdg_get_blocking_mode(conn)) && (status == osdg_closed))
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
        
        if (!devismart_config_connect(conn))
            return;
    case osdg_error:
        printf("Pairing failed: ");
        print_client_error(conn);
        break;
    default:
        printf("Invalid pairing status %u\n", status); /* You should not see this */
        break;
    }
}

static osdg_result_t default_peer_receive_data(osdg_connection_t conn, const void *data, unsigned int length)
{
    printf("Received data from the peer: ");
    dump_data(data, length);
    return osdg_no_error;
}

static int blockingMode = 0;

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

  osdg_set_blocking_mode(peer, blockingMode);
  osdg_set_state_change_callback(peer, peer_status_changed);

  if (!strcmp(arg, DEVISMART_PROTOCOL_NAME))
    receiveFunc = devismart_receive_data;
  else
    receiveFunc = default_peer_receive_data;

  res = osdg_set_receive_data_callback(peer, receiveFunc);
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
  osdg_result_t res;

  peer = osdg_connection_create();
  if (!peer)
  {
      printf("Failed to create peer!\n");
      return;
  }

  osdg_set_state_change_callback(peer, pairing_status_changed);

  res = osdg_pair_remote(client, peer, otp);
  if (res != osdg_no_error)
  {
      printf("Failed to start connection!\n");
      osdg_connection_destroy(peer);
      return;
  }
  else if (osdg_get_blocking_mode(peer))
  {
      osdg_connection_destroy(peer);
  }
}

static int getConnectionIdx(char **argStr)
{
    const char *arg = getWord(argStr);
    char *end;
    unsigned int idx = strtoul(arg, &end, 10);

    if (arg == end || idx >= num_peers || peers[idx] == NULL)
    {
        printf("Invalid peer index %s!\n", arg);
        return -1;
    }

    return idx;
}

static void close_connection(char *argStr)
{
    int idx = getConnectionIdx(&argStr);

    if (idx == -1)
        return;

    osdg_connection_close(peers[idx]);
    if (osdg_get_blocking_mode(peers[idx]))
    {
        osdg_connection_destroy(peers[idx]);
        peers[idx] = NULL;
    }
}

static void send_data(char *argStr)
{
    int idx = getConnectionIdx(&argStr);

    if (idx == -1)
        return;

    osdg_result_t res = devismart_send(peers[idx], argStr);

    if (res != osdg_no_error)
        print_result(res);
}

static void set_ping_interval(osdg_connection_t client, char *argStr)
{
    const char *arg = getWord(&argStr);
    char *end;
    unsigned int val = strtoul(arg, &end, 10);
    osdg_result_t r;

    if (arg == end)
    {
        printf("Invalid ping interval %s!\n", arg);
        return;
    }

    r = osdg_set_ping_interval(client, val);
    if (r != osdg_no_error)
    {
        printf("Failed to set ping interval: ");
        print_result(r);
    }
}

static void set_blocking_mode(char *argStr)
{
    const char *arg = getWord(&argStr);

    if (!strcmp(arg, "on"))
        blockingMode = 1;
    else if (!strcmp(arg, "off"))
        blockingMode = 0;
    else if (*arg)
        printf("Invalid blocking mode argument: %s\n", arg);

    printf("Blocking mode is now %s\n", blockingMode ? "on" : "off");
}

static osdg_connection_t client;

osdg_connection_t get_grid_connection(void)
{
    return client;
}

int main(int argc, const char *const *argv)
{
  unsigned int logmask = OSDG_LOG_ERRORS;
  osdg_key_t clientKey;
  int i;
  osdg_result_t r;

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
      printf("Failed to initialize OSDG: ");
      print_result(r);
      return 255;
  }

  i = read_file(clientKey, sizeof(clientKey), "osdg_test_private_key.bin");
  if (!i)
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

  i = read_file(&pairings, sizeof(pairings), "osdg_test_pairings.bin");
  if (i)
    pairings.count = 0;

  client = osdg_connection_create();
  if (!client)
  {
    printf("Failed to create client!\n");
    return 255;
  }

  osdg_set_blocking_mode(client, 1);
  osdg_set_state_change_callback(client, grid_status_changed);
  osdg_set_private_key(client, clientKey);

  r = osdg_connect_to_danfoss(client);
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
          printf("help                       - this help\n"
                 "close [connection #]       - close a connection\n"
                 "connect [peer # or ID]     - connect to peer by index or raw ID\n"
                 "list pairings              - list known pairings\n"
                 "list peers                 - list current connections\n"
                 "pair [OTP]                 - pair with the given OTP\n"
                 "ping [interval]            - set grid ping interval in seconds\n"
                 "send [connection #] [data] - send data to a peer\n"
                 "blocking [on|off]          - set blocking mode\n"
                 "quit                       - end session\n"
                 "whoami                     - print own peer information\n");
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
        else if (!strcmp(cmd, "ping"))
        {
            set_ping_interval(client, p);
        }
        else if (!strcmp(cmd, "send"))
        {
            send_data(p);
        }
        else if (!strcmp(cmd, "blocking"))
        {
            set_blocking_mode(p);
        }
        else if (!strcmp(cmd, "quit"))
        {
          break;
        }
        else if (!strcmp(cmd, "whoami"))
        {
            printf("Private key: ");
            hexdump(clientKey, sizeof(osdg_key_t));
            printf("\nPeer ID    : ");
            hexdump(osdg_get_my_peer_id(client), sizeof(osdg_key_t));
            putchar('\n');
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
  osdg_connection_destroy(client);

  osdg_shutdown();
  return 0;
}
