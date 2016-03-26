#include "binflow.h"

void xfree(void *p)
{
    if (p != NULL)
        free(p);
}

char *_strdupa(const char *s)
{
    char *p = alloca(strlen(s) + 1);
    strcpy(p, s);
    return p;
}

void *heapAlloc(unsigned int len)
{
    uint8_t *mem = malloc(len);

    if (!mem) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    return mem;
}

char *xstrdup(const char *s)
{
    char *p = strdup(s);

    if (p == NULL) {
        perror("strdup");
        exit(EXIT_FAILURE);
    }

    return p;
}

char *xfmtstrdup(char *fmt, ...)
{
    char *s, buf[512];
    va_list va;

    va_start(va, fmt);
    vsnprintf(buf, sizeof(buf), fmt, va);
    s = xstrdup(buf);

    return s;
}
