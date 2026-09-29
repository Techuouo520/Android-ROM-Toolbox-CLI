#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// Every descriptor carries image or file data, so text mode translation must never apply.
__attribute__((constructor)) static void artb_mkfs_binary_mode(void) { _set_fmode(_O_BINARY); }

// TRE translates its error strings through gettext; untranslated text avoids libintl and its registry lookups.
char *libintl_gettext(const char *message) { return (char *)message; }

char *strndup(const char *text, size_t size) {
    size_t length = strnlen(text, size);
    char *copy = malloc(length + 1);
    if (!copy) return NULL;
    memcpy(copy, text, length);
    copy[length] = 0;
    return copy;
}

// POSIX unlinks an open temporary file; Windows deletes it when the last handle closes instead.
int artb_mkfs_tmpfile(void) {
    wchar_t directory[MAX_PATH + 1], name[MAX_PATH + 1];
    DWORD length = GetTempPathW(MAX_PATH + 1, directory);
    if (!length || length > MAX_PATH || !GetTempFileNameW(directory, L"bke", 0, name)) return -EIO;
    HANDLE file = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (file == INVALID_HANDLE_VALUE) return -EIO;
    int fd = _open_osfhandle((intptr_t)file, _O_RDWR | _O_BINARY);
    if (fd < 0) { CloseHandle(file); return -EMFILE; }
    return fd;
}
