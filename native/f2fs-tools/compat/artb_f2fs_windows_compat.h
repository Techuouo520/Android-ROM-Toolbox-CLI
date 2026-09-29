#pragma once
#ifdef _WIN32
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include "artb_winfs.h"

#ifndef S_IFSOCK
#define S_IFSOCK 0140000
#endif
#ifndef S_ISSOCK
#define S_ISSOCK(mode) (((mode) & S_IFMT) == S_IFSOCK)
#endif
#ifndef S_ISUID
#define S_ISUID 04000
#endif
#ifndef S_ISGID
#define S_ISGID 02000
#endif
#ifndef S_ISVTX
#define S_ISVTX 01000
#endif
#ifndef S_IRWXG
#define S_IRWXG 00070
#endif
#ifndef S_IRWXO
#define S_IRWXO 00007
#endif

// sload reads the tree through these; placeholders for Cygwin-style symlinks come back as S_IFLNK.
#define lstat(path, st) artb_lstat(path, st)
#define readlink(path, buffer, size) artb_readlink(path, buffer, size)

#ifdef __cplusplus
extern "C" {
#endif
// Byte-order sorting, as glibc alphasort behaves in the C locale, keeps the image layout identical on every host.
int artb_f2fs_scandir(const char *dir, struct dirent ***names, int (*filter)(const struct dirent *), int (*compare)(const struct dirent **, const struct dirent **));
int artb_f2fs_alphasort(const struct dirent **a, const struct dirent **b);
#ifdef __cplusplus
}
#endif
#define scandir artb_f2fs_scandir
#define alphasort artb_f2fs_alphasort
#endif
