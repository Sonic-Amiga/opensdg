#include <stdarg.h>
#include <stdio.h>

#include "logging.h"
#include "opensdg.h"

unsigned int log_mask = -1;

void _log(unsigned int mask, const char *format, ...)
{
  /* mask is for future */
  va_list ap;

  va_start(ap, format);
  vprintf(format, ap);
  putchar('\n');
  va_end(ap);
}

void Dump(const unsigned char *data, size_t length)
{
  unsigned int i;

  if (length == 0)
    return;

  for (i = 0; i < length; i++)
    printf("%02x", data[i]);
  putchar('\n');
}
