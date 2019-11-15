#ifndef _INTERNAL_PROTOCOL_H
#define _INTERNAL_PROTOCOL_H

#include <sodium.h>
#include <string.h>
#include "logging.h"

/* All the data come in bigendian format */
#define SWAP_4_BYTES(a, b, c, d) (((d) << 24) | ((c) << 16) | ((b) << 8) | (a))
#define SWAP_16(val) (((((unsigned short)val) & 0xff) << 8) | \
                      (((unsigned short)val) >> 8))
#define SWAP_64(val) ((((val) & 0x00000000000000ffULL) << 56) | \
                      (((val) & 0x000000000000ff00ULL) << 40) | \
                      (((val) & 0x0000000000ff0000ULL) << 24) | \
                      (((val) & 0x00000000ff000000ULL) << 8) | \
                      (((val) & 0x000000ff00000000ULL) >> 8) | \
                      (((val) & 0x0000ff0000000000ULL) >> 24) | \
                      (((val) & 0x00ff000000000000ULL) >> 40) | \
                       ((val) >> 56))

#pragma pack(1)

/* Packet header */
struct packet_header
{
  unsigned short size;    /* Size, excluding this field */
  unsigned int   magic;   /* Magic value of PACKET_MAGIC */
  unsigned int   command; /* Command */
};

/*
 * Since size includes magic and command  but not size itself, we have
 * these useful macros here
 */
#define PACKET_SIZE(header)  (SWAP_16((header)->size) + 2)
#define PAYLOAD_SIZE(header) (SWAP_16((header)->size) - 8)

/* Magic value */
#define PACKET_MAGIC SWAP_4_BYTES(0xf0, 0x9f, 0x90, 0x9f)

static inline void build_header(struct packet_header *header, int cmd, size_t size)
{
  header->size    = SWAP_16(size - 2);
  header->magic   = PACKET_MAGIC;
  header->command = cmd;
}

#define ENCRYPTED_BOX(x) unsigned char x[sizeof(struct x) - crypto_box_BOXZEROBYTES]

/*
 * Command and their full packet structures follow
 * The protocol is based on CurveCP (http://curvecp.org). It uses the same
 * procedures, but different packet format.
 */

#define CMD_TELL SWAP_4_BYTES('T', 'E', 'L', 'L') /* Request public key from the server */
/* TELL command has no payload */

#define CMD_WELC SWAP_4_BYTES('W', 'E', 'L', 'C') /* Public key response from the server */
struct packetWELC
{
  struct packet_header header;
  unsigned char        serverKey[crypto_box_PUBLICKEYBYTES]; /* Server's public key */
};

#define CMD_HELO SWAP_4_BYTES('H', 'E', 'L', 'O') /* CurveCP Hello */
struct packetHELO
{
  struct packet_header header;
  unsigned char        clientPubkey[crypto_box_PUBLICKEYBYTES]; /* Client public key*/
  unsigned long long   nonce;                                   /* Nonce value used for encryption */
  unsigned char        ciphertext[80];                          /* Encrypted zero message */
};

#define CMD_COOK SWAP_4_BYTES('C', 'O', 'O', 'K') /* CurveCP cookie */
#define curvecp_COOKIEBYTES 96
struct curvecp_cookie
{
    unsigned char outerPad[crypto_box_BOXZEROBYTES];                /* Outer padding for crypto_box_open() */
    unsigned char innerPad[crypto_box_BOXZEROBYTES];                /* Inner padding */
    unsigned char serverShortTermPubkey[crypto_box_PUBLICKEYBYTES]; /* Short-term server public key */
    unsigned char cookie[curvecp_COOKIEBYTES];                      /* Server cookie */
};

struct packetCOOK
{
  struct packet_header header;
  unsigned long long nonce[2];   /* Nonce value */
  ENCRYPTED_BOX(curvecp_cookie); /* Encrypted struct curvecp_cookue */
};


#define CMD_VOCH SWAP_4_BYTES('V', 'O', 'C', 'H') /* CurveCP voucher */
struct curvecp_vouch_inner
{
  unsigned char outerPad[crypto_box_BOXZEROBYTES];       /* Outer padding for crypto_box() */
  unsigned char innerPad[crypto_box_BOXZEROBYTES];       /* Inner padding */
  unsigned char clientPubkey[crypto_box_PUBLICKEYBYTES]; /* Client's short-term public key */
};

struct curvecp_vouch_outer
{
  unsigned char outerPad[crypto_box_BOXZEROBYTES];       /* Outer padding for crypto_box() */
  unsigned char innerPad[crypto_box_BOXZEROBYTES];       /* Inner padding */
  unsigned char clientPubkey[crypto_box_PUBLICKEYBYTES]; /* Client long-term public key */
  unsigned long long nonce[2];
  ENCRYPTED_BOX(curvecp_vouch_inner);                    /* Encrypted inner box */
  unsigned char haveCertificate;                         /* Certificate data presence flag */
  unsigned char certificate[0];                          /* Certificate data follows */
};

struct packetVOCH
{
  struct packet_header header;
  unsigned char cookie[curvecp_COOKIEBYTES]; /* Server cookie */
  unsigned long long nonce;                  /* Nonce value */
  ENCRYPTED_BOX(curvecp_vouch_outer);        /* Encrypted outer box */
  /* Ciphertext can be longer, check full packet length */
};

struct certificate_data
{
    unsigned char prefixLength; /* Length of the following string without trailing NULL */
    unsigned char prefix[12];   /* NULL-terminated string "certificate" */
    unsigned char keyLength;    /* Length of the license key */
    unsigned char key[128];     /* License key */
};

#define CMD_REDY SWAP_4_BYTES('R', 'E', 'D', 'Y') /* READY response from the server */
struct redy_payload
{
  unsigned char outerPad[crypto_box_BOXZEROBYTES]; /* Outer padding for crypto_box() */
  unsigned char innerPad[crypto_box_BOXZEROBYTES]; /* Inner padding */
  unsigned char unknown[1];                        /* We get at least one byte of unknown value */
};

struct packetREDY
{
  struct packet_header header;
  unsigned long long nonce;
  ENCRYPTED_BOX(redy_payload);
  /* Ciphertext can be longer; check full length of a packet */
};

#define CMD_MESG SWAP_4_BYTES('M', 'E', 'S', 'G') /* General incoming message */
struct DataPacket
{
  unsigned short size;    /* Payload size plus 1 (size of "dataType"). Bigendian */
  unsigned char  type;    /* Message data type, see below */
  unsigned char  data[0]; /* Serialized data start here */
};

struct mesg_payload
{
  unsigned char     outerPad[crypto_box_BOXZEROBYTES]; /* Outer padding for crypto_box() */
  unsigned char     innerPad[crypto_box_BOXZEROBYTES]; /* Inner padding */
  struct DataPacket data;                              /* Payload itself */
};

struct packetMESG
{
  struct packet_header header;
  unsigned long long nonce;
  ENCRYPTED_BOX(mesg_payload);
  /* Ciphertext can be longer; check full length of a packet */
};

/*
 * REDY and MESG share the same structure, just with different payloads
 * and different nonce prefix, so this macro is applicable to both
 */
#define MESG_CIPHERTEXT_SIZE(header) (PACKET_SIZE(header) - offsetof(struct packetMESG, mesg_payload))

#pragma pack()

/* Shorthands to zero paddings */
static inline void zero_pad(unsigned char *pad)
{
  memset(pad, 0, crypto_box_BOXZEROBYTES * 2);
}

static inline void zero_outer_pad(unsigned char *pad)
{
  memset(pad - crypto_box_BOXZEROBYTES, 0, crypto_box_BOXZEROBYTES);
}

/* CurveCP nonces. For convenience we represent them as three 64-bit values. */
union curvecp_nonce
{
    unsigned char data[crypto_box_NONCEBYTES];
    unsigned long long value[3];
};

static inline void build_short_term_nonce(union curvecp_nonce *nonce, const char *text, unsigned long long value)
{
    memcpy(nonce->value, text, 16);
    nonce->value[2] = value;
}

static inline void build_long_term_nonce(union curvecp_nonce *nonce, const char *text, const unsigned long long *values)
{
    memcpy(nonce->value, text, 8);
    nonce->value[1] = values[0];
    nonce->value[2] = values[1];
}

static inline void build_random_long_term_nonce(union curvecp_nonce *nonce, const char *text)
{
    memcpy(nonce->value, "CurveCPV", 8);
    randombytes((unsigned char *)&nonce->value[1], 16);
}

/* Grid message types */
#define MSG_FORWARD_REMOTE   0
#define MSG_PROTOCOL_VERSION 1
#define MSG_FORWARD_REPLY    2
#define MSG_CALL_REMOTE      10
#define MSG_REMOTE_REPLY     11

#define FORWARD_REMOTE_MAGIC     0xF09D8C95
#define FORWARD_REMOTE_SIGNATURE "Mdg-NaCl/binary"
#define PROTOCOL_VERSION_MAGIC   0xF09D8CA8
#define PROTOCOL_VERSION_MAJOR   1
#define PROTOCOL_VERSION_MINOR   0

void build_header(struct packet_header *header, int cmd, size_t size);
int send_packet(struct packet_header *header, struct _osdg_client *client);
int receive_packet(struct _osdg_client *client);

int sendMESG(struct _osdg_client *client, unsigned char dataType, const void *data);
int start_connection(struct _osdg_client *conn);

#endif
