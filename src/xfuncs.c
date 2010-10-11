#include <stdio.h>
#include <stdlib.h>

#define NORETURN __attribute__ ((noreturn))
static NORETURN void die_out_of_memory()
{
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


