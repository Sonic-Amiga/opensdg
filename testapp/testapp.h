void hexdump(const unsigned char *data, unsigned int size);

static inline void dump_data(const unsigned char *data, unsigned int size)
{
    hexdump(data, size);
    putchar('\n');
}
