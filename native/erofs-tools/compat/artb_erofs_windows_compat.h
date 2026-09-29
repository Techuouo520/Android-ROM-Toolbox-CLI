#pragma once
#if defined(_WIN32)
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef unsigned int uint;
#ifdef __cplusplus
extern "C" {
#endif
#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif
#ifndef S_IFSOCK
#define S_IFSOCK 0140000
#endif
#ifndef S_ISSOCK
#define S_ISSOCK(mode) (((mode) & S_IFMT) == S_IFSOCK)
#endif
#ifndef S_ISLNK
#define S_ISLNK(mode) (((mode) & S_IFMT) == S_IFLNK)
#endif
#ifndef DT_UNKNOWN
#define DT_UNKNOWN 0
#define DT_FIFO 1
#define DT_CHR 2
#define DT_DIR 4
#define DT_BLK 6
#define DT_REG 8
#define DT_LNK 10
#define DT_SOCK 12
#endif
#ifndef major
#define major(device) ((unsigned int)(((device) >> 8) & 0xfff))
#define minor(device) ((unsigned int)((device) & 0xff))
#define makedev(major_value, minor_value) ((((major_value) & 0xfff) << 8) | ((minor_value) & 0xff))
#endif
#ifndef lstat
#define lstat(path, value) stat(path, value)
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#define geteuid() 1
#define lchown(path, owner, group) 0
int asprintf(char **value, const char *format, ...);
ssize_t pread(int fd, void *buffer, size_t count, off_t offset);
ssize_t pwrite(int fd, const void *buffer, size_t count, off_t offset);
int fsync(int fd);
int mknod(const char *path, mode_t mode, dev_t device);
void artb_register_parallel_fd(int fd);
void artb_unregister_parallel_fd(int fd);
int artb_set_file_times(const char *path, int64_t seconds, uint32_t nanoseconds);
#ifdef __cplusplus
}
#endif
#endif
