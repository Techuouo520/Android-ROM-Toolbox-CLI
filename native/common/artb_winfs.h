#pragma once

#ifdef _WIN32
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif
#ifndef S_ISLNK
#define S_ISLNK(mode) (((mode) & S_IFMT) == S_IFLNK)
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Returns 1 with the UTF-8 target length for a Cygwin symlink placeholder, 0 for any other entry and -1 on error.
int artb_symlink_length(const char *path, size_t *length);
// Copies a placeholder target without a terminator, matching readlink(2).
ssize_t artb_readlink(const char *path, char *buffer, size_t size);
// Reports the NTFS file index and link count, since Windows stat leaves st_ino and st_nlink unusable.
int artb_file_identity(const char *path, uint64_t *index, uint32_t *links);

#ifdef __cplusplus
}
#endif

// Inline so it uses the caller's struct stat layout, which depends on _FILE_OFFSET_BITS.
static inline int artb_lstat(const char *path, struct stat *st) {
    size_t length = 0;
    int kind;
    if (stat(path, st)) return -1;
    if (!S_ISREG(st->st_mode)) return 0;
    kind = artb_symlink_length(path, &length);
    if (kind < 0) return -1;
    if (kind > 0) {
        st->st_mode = (st->st_mode & ~S_IFMT) | S_IFLNK | 0777;
        st->st_size = (off_t)length;
    }
    return 0;
}
#endif
