#include "fnmatch.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <windows.h>

static int artb_match(const char *pattern, const char *value, int flags, int start) {
    for (;;) {
        char p = *pattern++;
        if (!p) return *value ? FNM_NOMATCH : 0;
        if (p == '*') {
            while (*pattern == '*') ++pattern;
            if (!*pattern) return (flags & FNM_PATHNAME) && strchr(value, '/') ? FNM_NOMATCH : 0;
            for (; *value && (!(flags & FNM_PATHNAME) || *value != '/'); ++value) if (!artb_match(pattern, value, flags, 0)) return 0;
            return artb_match(pattern, value, flags, 0);
        }
        if (!*value) return FNM_NOMATCH;
        if ((flags & FNM_PERIOD) && start && *value == '.' && (p == '*' || p == '?')) return FNM_NOMATCH;
        if (p == '?') {
            if ((flags & FNM_PATHNAME) && *value == '/') return FNM_NOMATCH;
            ++value;
            start = 0;
            continue;
        }
        if (p == '\\' && !(flags & FNM_NOESCAPE) && *pattern) p = *pattern++;
        if (p != *value++) return FNM_NOMATCH;
        start = (flags & FNM_PATHNAME) && p == '/';
    }
}

int fnmatch(const char *pattern, const char *value, int flags) { return artb_match(pattern, value, flags, 1); }

int asprintf(char **value, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int size = _vscprintf(format, args);
    va_end(args);
    if (size < 0) return -1;
    *value = malloc((size_t)size + 1);
    if (!*value) return -1;
    va_start(args, format);
    int written = vsnprintf(*value, (size_t)size + 1, format, args);
    va_end(args);
    if (written < 0) {
        free(*value);
        *value = NULL;
    }
    return written;
}

#define ARTB_PARALLEL_FD_LIMIT 256
#define ARTB_THREAD_HANDLE_SLOTS 4
#define ARTB_READ_WINDOWS 2
#define ARTB_READ_WINDOW_SIZE (256 * 1024)

static struct {
    volatile LONG generation;
    volatile LONG registered;
    HANDLE original;
} artb_parallel_fds[ARTB_PARALLEL_FD_LIMIT];

typedef struct {
    unsigned char *data;
    unsigned long long start;
    unsigned long long used;
    DWORD length;
} ArtbReadWindow;

typedef struct {
    int fd;
    LONG generation;
    HANDLE handle;
    ArtbReadWindow windows[ARTB_READ_WINDOWS];
} ArtbThreadReader;

static _Thread_local ArtbThreadReader artb_thread_readers[ARTB_THREAD_HANDLE_SLOTS];
static _Thread_local unsigned artb_thread_reader_next;
static _Thread_local unsigned long long artb_thread_clock;

void artb_register_parallel_fd(int fd) {
    if (fd < 0 || fd >= ARTB_PARALLEL_FD_LIMIT) return;
    artb_parallel_fds[fd].original = (HANDLE)_get_osfhandle(fd);
    InterlockedIncrement(&artb_parallel_fds[fd].generation);
    InterlockedExchange(&artb_parallel_fds[fd].registered, 1);
}

void artb_unregister_parallel_fd(int fd) {
    if (fd < 0 || fd >= ARTB_PARALLEL_FD_LIMIT) return;
    InterlockedExchange(&artb_parallel_fds[fd].registered, 0);
    InterlockedIncrement(&artb_parallel_fds[fd].generation);
}

static ssize_t artb_read_at(HANDLE handle, void *buffer, DWORD count, unsigned long long offset) {
    OVERLAPPED operation = {0};
    operation.Offset = (DWORD)(offset & 0xffffffffu);
    operation.OffsetHigh = (DWORD)(offset >> 32);
    DWORD transferred = 0;
    if (!ReadFile(handle, buffer, count, &transferred, &operation)) {
        if (GetLastError() == ERROR_HANDLE_EOF) return 0;
        errno = EIO;
        return -1;
    }
    return (ssize_t)transferred;
}

// Synchronous handles serialize I/O per file object, so readers of a registered fd get a private handle per thread.
static ArtbThreadReader *artb_thread_reader(int fd) {
    if (fd < 0 || fd >= ARTB_PARALLEL_FD_LIMIT || !artb_parallel_fds[fd].registered) return NULL;
    LONG generation = artb_parallel_fds[fd].generation;
    for (unsigned slot = 0; slot < ARTB_THREAD_HANDLE_SLOTS; slot++) {
        ArtbThreadReader *reader = &artb_thread_readers[slot];
        if (reader->handle && reader->fd == fd && reader->generation == generation) return reader;
    }
    HANDLE handle = ReOpenFile(artb_parallel_fds[fd].original, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_FLAG_SEQUENTIAL_SCAN);
    if (handle == INVALID_HANDLE_VALUE) return NULL;
    ArtbThreadReader *reader = &artb_thread_readers[artb_thread_reader_next++ % ARTB_THREAD_HANDLE_SLOTS];
    if (reader->handle) CloseHandle(reader->handle);
    for (unsigned index = 0; index < ARTB_READ_WINDOWS; index++) reader->windows[index].length = 0;
    reader->fd = fd;
    reader->generation = generation;
    reader->handle = handle;
    return reader;
}

// EROFS reads 4 KiB clusters one by one, so each miss fills a 256 KiB window and later reads are served from memory.
static ssize_t artb_windowed_read(ArtbThreadReader *reader, void *buffer, size_t count, unsigned long long offset) {
    if (count >= ARTB_READ_WINDOW_SIZE) return artb_read_at(reader->handle, buffer, (DWORD)count, offset);
    ArtbReadWindow *window = NULL;
    for (unsigned index = 0; index < ARTB_READ_WINDOWS; index++) {
        ArtbReadWindow *candidate = &reader->windows[index];
        if (candidate->length && offset >= candidate->start && offset + count <= candidate->start + candidate->length) {
            window = candidate;
            break;
        }
    }
    if (!window) {
        window = &reader->windows[0];
        for (unsigned index = 1; index < ARTB_READ_WINDOWS; index++) {
            if (reader->windows[index].used < window->used) window = &reader->windows[index];
        }
        if (!window->data && !(window->data = (unsigned char *)malloc(ARTB_READ_WINDOW_SIZE))) return artb_read_at(reader->handle, buffer, (DWORD)count, offset);
        unsigned long long start = offset & ~4095ULL;
        ssize_t filled = artb_read_at(reader->handle, window->data, ARTB_READ_WINDOW_SIZE, start);
        if (filled < 0) {
            window->length = 0;
            return -1;
        }
        window->start = start;
        window->length = (DWORD)filled;
        if (offset >= start + (unsigned long long)filled) return 0;
    }
    window->used = ++artb_thread_clock;
    size_t available = (size_t)(window->start + window->length - offset);
    size_t copied = count < available ? count : available;
    memcpy(buffer, window->data + (offset - window->start), copied);
    return (ssize_t)copied;
}

static ssize_t artb_positioned_io(int fd, void *buffer, size_t count, off_t offset, int write_mode) {
    HANDLE handle = (HANDLE)_get_osfhandle(fd);
    if (handle == INVALID_HANDLE_VALUE || count > MAXDWORD) {
        errno = EINVAL;
        return -1;
    }
    OVERLAPPED operation = {0};
    operation.Offset = (DWORD)((unsigned long long)offset & 0xffffffffu);
    operation.OffsetHigh = (DWORD)((unsigned long long)offset >> 32);
    DWORD transferred = 0;
    // Positioned I/O on a synchronous handle moves the file pointer, which POSIX pread and pwrite must keep.
    LARGE_INTEGER zero = {0}, saved;
    BOOL restore = SetFilePointerEx(handle, zero, &saved, FILE_CURRENT);
    BOOL ok = write_mode ? WriteFile(handle, buffer, (DWORD)count, &transferred, &operation) : ReadFile(handle, buffer, (DWORD)count, &transferred, &operation);
    DWORD failure = ok ? 0 : GetLastError();
    if (restore) SetFilePointerEx(handle, saved, NULL, FILE_BEGIN);
    SetLastError(failure);
    if (!ok) {
        DWORD error = GetLastError();
        if (!write_mode && error == ERROR_HANDLE_EOF) return 0;
        errno = EIO;
        return -1;
    }
    return (ssize_t)transferred;
}

ssize_t pread(int fd, void *buffer, size_t count, off_t offset) {
    ArtbThreadReader *reader = artb_thread_reader(fd);
    if (!reader || count > MAXDWORD || offset < 0) return artb_positioned_io(fd, buffer, count, offset, 0);
    return artb_windowed_read(reader, buffer, count, (unsigned long long)offset);
}

ssize_t pwrite(int fd, const void *buffer, size_t count, off_t offset) { return artb_positioned_io(fd, (void *)buffer, count, offset, 1); }

int fsync(int fd) { return _commit(fd); }

int mknod(const char *path, mode_t mode, dev_t device) {
    (void)mode;
    (void)device;
    int fd = _open(path, _O_CREAT | _O_EXCL | _O_WRONLY | _O_BINARY, _S_IREAD | _S_IWRITE);
    if (fd < 0) return -1;
    return _close(fd);
}
