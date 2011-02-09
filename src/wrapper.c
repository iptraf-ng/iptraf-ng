
#define _GNU_SOURCE
#include "iptraf-ng-compat.h"

// Die if we can't allocate size bytes of memory.
void *xmalloc(size_t size)
{
    void *ptr = malloc(size);
    if (ptr == NULL && size != 0)
        die("Out of memory, xmalloc failed");
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
        die("Out of memory, xcalloc failed");
    return ptr;
}

void *xrealloc(void *ptr, size_t size)
{
    void *ret = realloc(ptr, size);
    if (!ret && !size)
        die("Out of memory, xrealloc failed");
    return ret;
}

char* xvasprintf(const char *format, va_list p)
{
    int r;
    char *string_ptr;

    // GNU extension
    r = vasprintf(&string_ptr, format, p);
    if (r < 0)
        die("Out of memory, xvasprintf failed");
    return string_ptr;
}

// Die if we can't copy a string to freshly allocated memory.
char* xstrdup(const char *s)
{
	if (!s)
		return NULL;

	char *t = strdup(s);

	if (!t)
		die("Out of memory, %s failed", __func__);

	return t;
}

