
#define _GNU_SOURCE
#include "iptraf-ng-compat.h"

static NORETURN void die_out_of_memory()
{
    fprintf(stderr, "fatal: out of memory\n");
    exit(EXIT_FAILURE);
}

// Die if we can't allocate size bytes of memory.
void *xmalloc(size_t size)
{
    void *ptr = malloc(size);
    if (ptr == NULL && size != 0)
        die_out_of_memory();
    return ptr;
}

void* xmallocz(size_t size)
{
    void *ptr = xmalloc(size);
    memset(ptr, 0, size);
    return ptr;
}

void *xcalloc(size_t nmemb, size_t size)
{
    void *ptr = calloc(nmemb, size);
    if (!ptr && (!nmemb || !size))
        die_out_of_memory();
    return ptr;
}

void *xrealloc(void *ptr, size_t size)
{
    void *ret = realloc(ptr, size);
    if (!ret && !size)
        die_out_of_memory();
    return ret;
}

char* xvasprintf(const char *format, va_list p)
{
    int r;
    char *string_ptr;

    // GNU extension
    r = vasprintf(&string_ptr, format, p);
    if (r < 0)
        die_out_of_memory();
    return string_ptr;
}

