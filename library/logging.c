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

void _dump(unsigned int mask, const unsigned char *data, size_t length, const char *format, ...)
{
    /* mask is for future */
    va_list ap;

    va_start(ap, format);
    vprintf(format, ap);

    if (length > 0)
    {
        size_t i;

        printf(": ");
        for (i = 0; i < length; i++)
            printf("%02x", data[i]);
    }

    putchar('\n');
}
