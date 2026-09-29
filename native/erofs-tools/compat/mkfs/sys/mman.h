#pragma once
#include <stddef.h>
#include <sys/types.h>

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MAP_FAILED ((void *)-1)

// erofs-utils treats mapping as optional and falls back to pread when it fails.
static inline void *mmap(void *address, size_t length, int protection, int flags, int fd, off_t offset) {
    (void)address;
    (void)length;
    (void)protection;
    (void)flags;
    (void)fd;
    (void)offset;
    return MAP_FAILED;
}

static inline int munmap(void *address, size_t length) {
    (void)address;
    (void)length;
    return 0;
}
