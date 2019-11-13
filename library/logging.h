#ifndef _INTERNAL_LOGGING_H
#define _INTERNAL_LOGGING_H

/* At some point these will likely go public */
#define LOG_ERRORS     0x01 /* Errors */
#define LOG_CONNECTION 0x02 /* Connection events */
#define LOG_PROTOCOL   0x04 /* Protocol */
#define LOG_PACKETS    0x08 /* Raw packets */

extern unsigned int log_mask;

#define LOG(mask, ...)         \
  if (log_mask & LOG_ ## mask) \
    _log(LOG_ ## mask, __VA_ARGS__)

#define DUMP(mask, data, size, ...) \
  if (log_mask & LOG_ ## mask)      \
    _dump(LOG_ ## mask, data, size, __VA_ARGS__)

void _log(unsigned int mask, const char *format, ...);
void _dump(unsigned int mask, const unsigned char *data, size_t len, const char *format, ...);

#endif
