#ifndef _INTERNAL_LOGGING_H
#define _INTERNAL_LOGGING_H

#include "opensdg.h"

extern unsigned int log_mask;

#define LOG(mask, ...)              \
  if (log_mask & OSDG_LOG_ ## mask) \
    _log(OSDG_LOG_ ## mask, __VA_ARGS__)

#define DUMP(mask, data, size, ...) \
  if (log_mask & OSDG_LOG_ ## mask) \
    _dump(OSDG_LOG_ ## mask, data, size, __VA_ARGS__)

void _log(unsigned int mask, const char *format, ...);
void _dump(unsigned int mask, const unsigned char *data, size_t len, const char *format, ...);

#endif
