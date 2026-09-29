#pragma once
#if defined(_WIN32)
#include <io.h>
#include <stdlib.h>
#include <string.h>
#include "artb_winfs.h"
#ifdef __cplusplus
extern "C" {
#endif
#define lstat(path, value) artb_lstat(path, value)
#define readlink(path, buffer, size) artb_readlink(path, buffer, size)
#define realpath(path, resolved) _fullpath(resolved, path, 32768)
#define getpagesize() 4096
#define getuid() 0
#define getgid() 0
#define fchmod(fd, mode) 0
// Sizes the asynchronous build queue; the UCRT allows 8192 descriptors in total.
#define _POSIX_OPEN_MAX 2048
char *strndup(const char *text, size_t size);
int artb_mkfs_tmpfile(void);
#ifdef __cplusplus
}
#endif
#endif
