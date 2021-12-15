#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "print_util.h"

void my_printl(const char* fname, const char* fmt, ...)
{
    char ebuf[BUFSIZ] = { '\0' };
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    snprintf(ebuf, sizeof(ebuf), "LOG: %s: %s", fname, buf);
    puts(ebuf);
}

void my_printe(const char* fname, const char* fmt, ...)
{
    char ebuf[BUFSIZ] = { '\0' };
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    snprintf(ebuf, sizeof(ebuf), "Error: %s failed!: %s", fname, buf);
    puts(ebuf);
    abort(); // For debugging
}