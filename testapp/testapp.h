#define AS_HEX(l) ((l) * 2 + 1)

void hexdump(const unsigned char *data, unsigned int size);
int add_pairing(osdg_key_t peerId, const char *description);
int save_pairings(void);

osdg_connection_t get_grid_connection(void);

void print_status(osdg_connection_t conn, enum osdg_connection_state status);
void print_client_error(osdg_connection_t client);

static inline void dump_data(const unsigned char *data, unsigned int size)
{
    hexdump(data, size);
    putchar('\n');
}

const char *getWord(char **p);
