#include "artb_erofs_windows_compat.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static wchar_t *artb_windows_path(const char *path) {
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    if (count <= 0) return NULL;
    wchar_t *plain = (wchar_t *)malloc((size_t)count * sizeof(wchar_t));
    if (!plain || MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, plain, count) <= 0) { free(plain); return NULL; }
    DWORD absoluteCount = GetFullPathNameW(plain, 0, NULL, NULL);
    if (!absoluteCount) { free(plain); return NULL; }
    wchar_t *absolute = (wchar_t *)malloc(((size_t)absoluteCount + 1) * sizeof(wchar_t));
    if (!absolute || !GetFullPathNameW(plain, absoluteCount + 1, absolute, NULL)) { free(plain); free(absolute); return NULL; }
    free(plain);
    const wchar_t *prefix = L"\\\\?\\";
    size_t prefixLength = 4;
    const wchar_t *source = absolute;
    if (absolute[0] == L'\\' && absolute[1] == L'\\') { prefix = L"\\\\?\\UNC\\"; prefixLength = 8; source += 2; }
    size_t sourceLength = wcslen(source);
    wchar_t *extended = (wchar_t *)malloc((prefixLength + sourceLength + 1) * sizeof(wchar_t));
    if (!extended) { free(absolute); return NULL; }
    memcpy(extended, prefix, prefixLength * sizeof(wchar_t));
    memcpy(extended + prefixLength, source, (sourceLength + 1) * sizeof(wchar_t));
    free(absolute);
    return extended;
}

int artb_set_file_times(const char *path, int64_t seconds, uint32_t nanoseconds) {
    wchar_t *wide = artb_windows_path(path);
    if (!wide) { errno = EINVAL; return -1; }
    HANDLE file = CreateFileW(wide, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    free(wide);
    if (file == INVALID_HANDLE_VALUE) { errno = EACCES; return -1; }
    uint64_t ticks = ((uint64_t)(seconds + 11644473600LL) * 10000000ULL) + nanoseconds / 100U;
    FILETIME value = {(DWORD)ticks, (DWORD)(ticks >> 32)};
    BOOL ok = SetFileTime(file, NULL, &value, &value);
    CloseHandle(file);
    if (!ok) { errno = EIO; return -1; }
    return 0;
}
