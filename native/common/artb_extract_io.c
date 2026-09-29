#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "artb_extract_io.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#endif

static const unsigned char zeros[65536];

#ifdef _WIN32
// Extended-length wide paths lift MAX_PATH and keep UTF-8 names intact.
static wchar_t *wide_path(const char *path) {
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    if (count <= 0) return NULL;
    wchar_t *plain = malloc((size_t)count * sizeof(wchar_t));
    if (!plain) return NULL;
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, plain, count);
    for (wchar_t *cursor = plain; *cursor; cursor++) if (*cursor == L'/') *cursor = L'\\';
    DWORD full = GetFullPathNameW(plain, 0, NULL, NULL);
    wchar_t *absolute = full ? malloc(((size_t)full + 1) * sizeof(wchar_t)) : NULL;
    if (!absolute || !GetFullPathNameW(plain, full + 1, absolute, NULL)) {
        free(plain);
        free(absolute);
        return NULL;
    }
    free(plain);
    const wchar_t *prefix = L"\\\\?\\";
    const wchar_t *source = absolute;
    if (absolute[0] == L'\\' && absolute[1] == L'\\') {
        prefix = L"\\\\?\\UNC\\";
        source += 2;
    }
    size_t length = wcslen(prefix) + wcslen(source) + 1;
    wchar_t *extended = malloc(length * sizeof(wchar_t));
    if (extended) {
        wcscpy(extended, prefix);
        wcscat(extended, source);
    }
    free(absolute);
    return extended;
}

ArtbFile artb_out_create(const char *path) {
    wchar_t *wide = wide_path(path);
    if (!wide) return ARTB_FILE_INVALID;
    HANDLE file = CreateFileW(wide, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    free(wide);
    return file;
}

int artb_out_write(ArtbFile file, const void *buffer, size_t length) {
    const unsigned char *cursor = buffer;
    while (length) {
        DWORD chunk = length > 0x40000000 ? 0x40000000 : (DWORD)length, written = 0;
        if (!WriteFile(file, cursor, chunk, &written, NULL) || written == 0) return -1;
        cursor += written;
        length -= written;
    }
    return 0;
}

int artb_file_close(ArtbFile file) { return CloseHandle(file) ? 0 : -1; }

ArtbFile artb_in_open(const char *path) {
    wchar_t *wide = wide_path(path);
    if (!wide) return ARTB_FILE_INVALID;
    HANDLE file = CreateFileW(wide, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(wide);
    return file;
}

int artb_in_read(ArtbFile file, void *buffer, size_t length, uint64_t offset) {
    unsigned char *cursor = buffer;
    while (length) {
        DWORD chunk = length > 0x40000000 ? 0x40000000 : (DWORD)length, got = 0;
        OVERLAPPED position;
        memset(&position, 0, sizeof(position));
        position.Offset = (DWORD)offset;
        position.OffsetHigh = (DWORD)(offset >> 32);
        if (!ReadFile(file, cursor, chunk, &got, &position) || got == 0) return -1;
        cursor += got;
        offset += got;
        length -= got;
    }
    return 0;
}

int artb_in_size(ArtbFile file, uint64_t *size) {
    LARGE_INTEGER value;
    if (!GetFileSizeEx(file, &value)) return -1;
    *size = (uint64_t)value.QuadPart;
    return 0;
}

int artb_make_dir(const char *path) {
    wchar_t *wide = wide_path(path);
    if (!wide) return -1;
    BOOL ok = CreateDirectoryW(wide, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
    free(wide);
    return ok ? 0 : -1;
}

int artb_make_symlink(const char *target, const char *path) {
    ArtbFile file = artb_out_create(path);
    if (file == ARTB_FILE_INVALID) return -1;
    int count = MultiByteToWideChar(CP_UTF8, 0, target, -1, NULL, 0);
    wchar_t *wide = count > 0 ? malloc((size_t)count * sizeof(wchar_t)) : NULL;
    int result = -1;
    if (wide && MultiByteToWideChar(CP_UTF8, 0, target, -1, wide, count) > 0) {
        static const char magic[] = "!<symlink>\xff\xfe";
        static const wchar_t terminator = 0;
        if (!artb_out_write(file, magic, sizeof(magic) - 1) && !artb_out_write(file, wide, (size_t)(count - 1) * sizeof(wchar_t)) && !artb_out_write(file, &terminator, sizeof(terminator))) result = 0;
    }
    free(wide);
    if (artb_file_close(file) && !result) result = -1;
    wchar_t *wide_name = wide_path(path);
    if (!result && (!wide_name || !SetFileAttributesW(wide_name, FILE_ATTRIBUTE_SYSTEM))) result = -1;
    free(wide_name);
    return result;
}

int artb_make_hardlink(const char *existing, const char *path) {
    wchar_t *from = wide_path(existing), *to = wide_path(path);
    // Volumes without hard links (FAT, exFAT, some shares) get a copy that keeps the timestamps.
    int result = from && to && (CreateHardLinkW(to, from, NULL) || CopyFileW(from, to, TRUE)) ? 0 : -1;
    free(from);
    free(to);
    return result;
}

int artb_set_times(const char *path, int64_t seconds, uint32_t nanoseconds) {
    wchar_t *wide = wide_path(path);
    if (!wide) return -1;
    HANDLE file = CreateFileW(wide, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    free(wide);
    if (file == INVALID_HANDLE_VALUE) return -1;
    uint64_t ticks = (uint64_t)(seconds + 11644473600LL) * 10000000ULL + nanoseconds / 100U;
    FILETIME value = {(DWORD)ticks, (DWORD)(ticks >> 32)};
    BOOL ok = SetFileTime(file, NULL, &value, &value);
    CloseHandle(file);
    return ok ? 0 : -1;
}

FILE *artb_open_text(const char *path) {
    wchar_t *wide = wide_path(path);
    FILE *file = wide ? _wfopen(wide, L"wb") : NULL;
    free(wide);
    return file;
}

void artb_sleep_ms(unsigned milliseconds) { Sleep(milliseconds); }

char **artb_utf8_argv(int argc, wchar_t **wide) {
    char **argv = calloc((size_t)argc + 1, sizeof(char *));
    for (int index = 0; argv && index < argc; index++) {
        int length = WideCharToMultiByte(CP_UTF8, 0, wide[index], -1, NULL, 0, NULL, NULL);
        argv[index] = length > 0 ? malloc((size_t)length) : NULL;
        if (!argv[index] || !WideCharToMultiByte(CP_UTF8, 0, wide[index], -1, argv[index], length, NULL, NULL)) return NULL;
    }
    return argv;
}
#else
ArtbFile artb_out_create(const char *path) { return open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644); }

int artb_out_write(ArtbFile file, const void *buffer, size_t length) {
    const unsigned char *cursor = buffer;
    while (length) {
        ssize_t written = write(file, cursor, length);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return -1;
        cursor += written;
        length -= (size_t)written;
    }
    return 0;
}

int artb_file_close(ArtbFile file) { return close(file); }

ArtbFile artb_in_open(const char *path) { return open(path, O_RDONLY | O_CLOEXEC); }

int artb_in_read(ArtbFile file, void *buffer, size_t length, uint64_t offset) {
    unsigned char *cursor = buffer;
    while (length) {
        ssize_t got = pread(file, cursor, length, (off_t)offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return -1;
        cursor += got;
        offset += (uint64_t)got;
        length -= (size_t)got;
    }
    return 0;
}

int artb_in_size(ArtbFile file, uint64_t *size) {
    struct stat info;
    if (fstat(file, &info)) return -1;
    *size = (uint64_t)info.st_size;
    return 0;
}

int artb_make_dir(const char *path) { return mkdir(path, 0755) == 0 || errno == EEXIST ? 0 : -1; }

int artb_make_symlink(const char *target, const char *path) { return symlink(target, path); }

static int copy_file(const char *existing, const char *path) {
    int in = open(existing, O_RDONLY | O_CLOEXEC);
    if (in < 0) return -1;
    struct stat info;
    int out = fstat(in, &info) ? -1 : artb_out_create(path), result = out < 0 ? -1 : 0;
    char *buffer = result ? NULL : malloc(1 << 20);
    if (!buffer) result = -1;
    for (ssize_t got; !result && (got = read(in, buffer, 1 << 20)) != 0;) {
        if (got < 0 && errno == EINTR) continue;
        result = got < 0 ? -1 : artb_out_write(out, buffer, (size_t)got);
    }
#ifdef __APPLE__
    struct timespec times[2] = {info.st_atimespec, info.st_mtimespec};
#else
    struct timespec times[2] = {info.st_atim, info.st_mtim};
#endif
    if (!result && futimens(out, times)) result = -1;
    free(buffer);
    close(in);
    if (out >= 0 && close(out)) result = -1;
    return result;
}

// Android denies link to the shell domain under /data and some filesystems lack hard links, so those get a copy with the same timestamps.
int artb_make_hardlink(const char *existing, const char *path) {
    if (!link(existing, path)) return 0;
    if (errno != EPERM && errno != EACCES && errno != EXDEV && errno != EMLINK && errno != ENOTSUP && errno != EOPNOTSUPP) return -1;
    return copy_file(existing, path);
}

int artb_set_times(const char *path, int64_t seconds, uint32_t nanoseconds) {
    struct timespec times[2] = {{(time_t)seconds, (long)nanoseconds}, {(time_t)seconds, (long)nanoseconds}};
    return utimensat(AT_FDCWD, path, times, AT_SYMLINK_NOFOLLOW);
}

FILE *artb_open_text(const char *path) { return fopen(path, "wb"); }

void artb_sleep_ms(unsigned milliseconds) {
    struct timespec delay = {milliseconds / 1000, (long)(milliseconds % 1000) * 1000000L};
    nanosleep(&delay, NULL);
}
#endif

int artb_out_zeros(ArtbFile file, uint64_t length) {
    while (length) {
        size_t chunk = length > sizeof(zeros) ? sizeof(zeros) : (size_t)length;
        if (artb_out_write(file, zeros, chunk)) return -1;
        length -= chunk;
    }
    return 0;
}

static int compare_strings(const void *left, const void *right) { return strcmp(*(char *const *)left, *(char *const *)right); }

char *artb_find_case_collision(const char *const *paths, size_t count) {
    char **folded = malloc((count ? count : 1) * sizeof(char *));
    if (!folded) return NULL;
    size_t filled = 0;
    for (; filled < count; filled++) {
        folded[filled] = strdup(paths[filled]);
        if (!folded[filled]) break;
        for (char *cursor = folded[filled]; *cursor; cursor++) if (*cursor >= 'A' && *cursor <= 'Z') *cursor = (char)(*cursor - 'A' + 'a');
    }
    qsort(folded, filled, sizeof(char *), compare_strings);
    char *collision = NULL;
    for (size_t index = 1; index < filled && !collision; index++) {
        if (!strcmp(folded[index - 1], folded[index])) collision = strdup(folded[index]);
    }
    for (size_t index = 0; index < filled; index++) free(folded[index]);
    free(folded);
    return collision;
}
