#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "opensdg.h"
#include "jsmn.h"
#include "devismart.h"
#include "testapp.h"

static int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
  if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}

static char *jsonstrdup(const char *json, jsmntok_t *tok)
{
  /* Reinvent strndup(); Windows doesn't have it. */
  int len = tok->end - tok->start;
  char *str = malloc(len + 1);

  memcpy(str, json + tok->start, len);
  str[len] = 0;
  return str;
}

/*
 * What is going on here is NOT communication with thermostats.
 * This code handles peer-to-peer communication with the DEVISmart app,
 * used to share houses. This is the only legitimate way to add a client
 * to an already running installation.
 * Communication here is done in JSON and is pretty self-explanatory.
 */
static const char *user_name = "DEVIComm test";

static int devismart_request_configuration(osdg_connection_t connection)
{
  char hexed[AS_HEX(sizeof(osdg_key_t))];
  char json[1024];
  int len;
  
  printf("Requesting DEVISmart config on connection %p\n", connection);

  osdg_bin_to_hex(hexed, sizeof(hexed), osdg_get_my_peer_id(), sizeof(osdg_key_t));
  /*
   * If chunkedMessage parameter is set to true, the whole data will be split
   * into 512-byte long chunks and sent as separate packets; we would have
   * to put them together during receiving; we don't want to do that.
   * In this case a header is sent in the first packet, describing total
   * length of the configuration data. See struct ConfigDataHeader.
   * As of DEVISmart v1.2 this parameter is optional and can be completely
   * omitted; default value is false. However we set it to true because
   * otherwise long configurations cannot be sent due to buffer size limit
   * in the mdglib.
   */
  len = sprintf(json, "{\"phoneName\":\"%s\",\"phonePublicKey\":\"%s\",\"chunkedMessage\":true}", user_name, hexed);
  
  printf("Sending request: %s\n", json);
  return osdg_send_data(connection, json, len);
}

struct ConfigDataHeader
{
  unsigned int start;  /* Always 0, used for presence detection */
  unsigned int length; /* Total length of the following data */
};

static int parse_config_data(const char *json, int size)
{
    /*
     * Received data is a JSON and it looks like this (i've removed my peer ID):
     * {"houseName":"My Flat","houseEditUsers":true,"rooms":[{"roomName":"Living room","peerId":"<undisclosed>","zone":"Living","sortOrder":0}]}
     */
    jsmn_parser p;
    jsmntok_t t[1024];
    int r, i, j, k;

    jsmn_init(&p);
    r = jsmn_parse(&p, json, size, t, sizeof(t) / sizeof(t[0]));

    if (r < 0) {
        printf("Failed to parse configuration JSON: %d\n", r);
        return -1;
    }

    for (i = 1; i < r; i++)
    {
        if ((jsoneq(json, &t[i], "rooms") == 0) && (t[i + 1].type == JSMN_ARRAY))
        {
            for (j = 0; j < t[i + 1].size; j++) {
                jsmntok_t *g = &t[i + j + 2];
                char *roomName = NULL;
                char *roomPeer = NULL;

                if (g[0].type != JSMN_OBJECT)
                {
                    printf("JSON error: \"rooms\" value is not an object!\n");
                    return 1;
                }

                for (k = 1; k < g[0].size; k += 2)
                {
                    if (jsoneq(json, &g[k], "roomName") == 0) {
                        roomName = jsonstrdup(json, &g[k + 1]);
                    } else if (jsoneq(json, &g[k], "peerId") == 0) {
                        roomPeer = jsonstrdup(json, &g[k + 1]);
                    }
                }

                if (roomName && roomPeer)
                {
                    osdg_key_t device_id;

                    printf("Adding room %s %s\n", roomPeer, roomName);

                    if (!osdg_hex_to_bin(device_id, sizeof(device_id), roomPeer, sizeof(osdg_key_t) * 2, NULL, NULL, NULL)) {
                        add_pairing(device_id, roomName);
                    } else {
                        printf("Malformed room %s peer ID: %s\n", roomName, roomPeer);
                    }
                }

                free(roomName);
                free(roomPeer);
            }

            i += t[i + 1].size + 1;
        }
    }

    return 0;
}

struct ChunkedData
{
    unsigned int length;
    unsigned int received;
    char json[0];
};

static osdg_result_t devismart_receive_config_data(osdg_connection_t conn, const void *ptr, unsigned int size)
{
  struct ChunkedData *cd = osdg_get_user_data(conn);
  const char *data = ptr;
  int res;

  if (size > sizeof(struct ConfigDataHeader))
  {
    const struct ConfigDataHeader *header = (struct ConfigDataHeader *)data;
  
    if (header->start == 0)
    {
      cd = malloc(sizeof(struct ChunkedData) + header->length);

      printf("Full size of chunked data: %d\n", header->length);
      cd->length = header->length;
      cd->received = 0;

      osdg_set_user_data(conn, cd);

      data += sizeof(struct ConfigDataHeader);
      size -= sizeof(struct ConfigDataHeader);
    }
  }

  printf("Received configuration data:\n%.*s\n", size, data);  

  if (cd)
  {
      if (cd->received + size > cd->length)
      {
          printf("Length overrun (%d vs %d)!\n", cd->received + size, cd->length);
          return osdg_protocol_error;
      }

      memcpy(&cd->json[cd->received], data, size);
      cd->received += size;

      if (cd->received < cd->length)
          return osdg_no_error; // Need more data

      res = parse_config_data(cd->json, cd->length);
      osdg_set_user_data(conn, NULL);
      free(cd);
  }
  else
  {
      res = parse_config_data(data, size);
  }

  if (!res)
  {
      osdg_connection_close(conn);
      return osdg_no_error;
  }

  return osdg_protocol_error;
}

static void devismart_config_status_changed(osdg_connection_t conn, enum osdg_connection_state status)
{
    printf("DeviSmart config");
    print_status(conn, status);

    if (status == osdg_connected)
    {
        int ret = devismart_request_configuration(conn);

        if (!ret)
            return;

        print_client_error(conn);
    }

    osdg_connection_destroy(conn);
}

int devismart_config_connect(osdg_connection_t conn)
{
    const unsigned char *peerId = osdg_get_peer_id(conn);

    osdg_set_state_change_callback(conn, devismart_config_status_changed);
    osdg_set_receive_data_callback(conn, devismart_receive_config_data);

    return osdg_connect_to_remote(get_grid_connection(), conn, peerId, PROTOCOL_DEVISMART_CONFIG);
}