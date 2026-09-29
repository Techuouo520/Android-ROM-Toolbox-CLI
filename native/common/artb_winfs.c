#ifdef _WIN32
#include "artb_winfs.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define ARTB_SYMLINK_MAGIC "!<symlink>"
#define ARTB_SYMLINK_MAGIC_SIZE 10
#define ARTB_SYMLINK_MAX_SIZE 65536

static wchar_t *wide_path(const char *path) {
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    if (count <= 0) { errno = EINVAL; return NULL; }
    wchar_t *plain = malloc((size_t)count * sizeof(wchar_t));
    if (!plain) { errno = ENOMEM; return NULL; }
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, plain, count);
    DWORD full = GetFullPathNameW(plain, 0, NULL, NULL);
    wchar_t *absolute = full ? malloc(((size_t)full + 8) * sizeof(wchar_t)) : NULL;
    if (!absolute) { free(plain); errno = full ? ENOMEM : EINVAL; return NULL; }
    // The \\?\ prefix lifts the MAX_PATH limit for deep partition trees.
    wcscpy(absolute, L"\\\\?\\");
    if (!GetFullPathNameW(plain, full, absolute + 4, NULL)) { free(plain); free(absolute); errno = EINVAL; return NULL; }
    free(plain);
    if (absolute[4] == L'\\' && absolute[5] == L'\\') {
        memmove(absolute + 8, absolute + 6, (wcslen(absolute + 6) + 1) * sizeof(wchar_t));
        memcpy(absolute, L"\\\\?\\UNC\\", 8 * sizeof(wchar_t));
    }
    return absolute;
}

static int set_errno_from_win32(void) {
    DWORD code = GetLastError();
    errno = code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND ? ENOENT : code == ERROR_ACCESS_DENIED ? EACCES : EIO;
    return -1;
}

// Reads a placeholder and returns the target as malloc'ed UTF-8, or NULL with *is_link = 0 for ordinary files.
static char *read_placeholder(const char *path, int *is_link) {
    *is_link = 0;
    wchar_t *wide = wide_path(path);
    if (!wide) return NULL;
    DWORD attributes = GetFileAttributesW(wide);
    if (attributes == INVALID_FILE_ATTRIBUTES) { free(wide); set_errno_from_win32(); return NULL; }
    if (!(attributes & FILE_ATTRIBUTE_SYSTEM) || (attributes & FILE_ATTRIBUTE_DIRECTORY)) { free(wide); errno = 0; return NULL; }
    HANDLE file = CreateFileW(wide, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(wide);
    if (file == INVALID_HANDLE_VALUE) { set_errno_from_win32(); return NULL; }
    LARGE_INTEGER size;
    char *data = NULL, *target = NULL;
    DWORD got = 0;
    if (!GetFileSizeEx(file, &size) || size.QuadPart < ARTB_SYMLINK_MAGIC_SIZE || size.QuadPart > ARTB_SYMLINK_MAX_SIZE) { CloseHandle(file); errno = 0; return NULL; }
    data = malloc((size_t)size.QuadPart + 2);
    if (!data) { CloseHandle(file); errno = ENOMEM; return NULL; }
    BOOL ok = ReadFile(file, data, (DWORD)size.QuadPart, &got, NULL);
    CloseHandle(file);
    if (!ok || got != (DWORD)size.QuadPart) { free(data); errno = EIO; return NULL; }
    if (memcmp(data, ARTB_SYMLINK_MAGIC, ARTB_SYMLINK_MAGIC_SIZE)) { free(data); errno = 0; return NULL; }
    data[got] = 0;
    data[got + 1] = 0;
    const char *body = data + ARTB_SYMLINK_MAGIC_SIZE;
    size_t remaining = got - ARTB_SYMLINK_MAGIC_SIZE;
    if (remaining >= 2 && (unsigned char)body[0] == 0xff && (unsigned char)body[1] == 0xfe) {
        size_t units = (remaining - 2) / 2, used = 0;
        const wchar_t *text = (const wchar_t *)(body + 2);
        while (used < units && text[used]) used++;
        int bytes = used ? WideCharToMultiByte(CP_UTF8, 0, text, (int)used, NULL, 0, NULL, NULL) : 0;
        target = malloc((size_t)bytes + 1);
        if (target && bytes) WideCharToMultiByte(CP_UTF8, 0, text, (int)used, target, bytes, NULL, NULL);
        if (target) target[bytes] = 0;
    } else {
        size_t used = strnlen(body, remaining);
        target = malloc(used + 1);
        if (target) { memcpy(target, body, used); target[used] = 0; }
    }
    free(data);
    if (!target) { errno = ENOMEM; return NULL; }
    *is_link = 1;
    return target;
}

int artb_symlink_length(const char *path, size_t *length) {
    int is_link;
    char *target = read_placeholder(path, &is_link);
    if (!is_link) return errno ? -1 : 0;
    *length = strlen(target);
    free(target);
    return 1;
}

ssize_t artb_readlink(const char *path, char *buffer, size_t size) {
    int is_link;
    char *target = read_placeholder(path, &is_link);
    if (!is_link) {
        if (!errno) errno = EINVAL;
        return -1;
    }
    size_t length = strlen(target);
    if (length > size) length = size;
    memcpy(buffer, target, length);
    free(target);
    return (ssize_t)length;
}

int artb_file_identity(const char *path, uint64_t *index, uint32_t *links) {
    wchar_t *wide = wide_path(path);
    if (!wide) return -1;
    HANDLE file = CreateFileW(wide, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    free(wide);
    if (file == INVALID_HANDLE_VALUE) return set_errno_from_win32();
    BY_HANDLE_FILE_INFORMATION info;
    BOOL ok = GetFileInformationByHandle(file, &info);
    CloseHandle(file);
    if (!ok) return set_errno_from_win32();
    *index = ((uint64_t)info.nFileIndexHigh << 32) | info.nFileIndexLow;
    *links = info.nNumberOfLinks;
    return 0;
}
#endif
