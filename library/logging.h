#ifndef _INTERNAL_LOGGING_H
#define _INTERNAL_LOGGING_H

#define LOG_ERRORS   0x01
#define LOG_PROTOCOL 0x02
#define LOG_DATA     0x04

extern unsigned int log_mask;

#define LOG(mask, ...)         \
  if (log_mask & LOG_ ## mask) \
    _log(LOG_ ## mask, __VA_ARGS__)

void _log(unsigned int mask, const char *format, ...);
void Dump(const unsigned char *data, unsigned int len);

#endif
