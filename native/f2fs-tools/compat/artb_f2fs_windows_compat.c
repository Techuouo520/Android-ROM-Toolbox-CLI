#ifdef _WIN32
#include "artb_f2fs_windows_compat.h"
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

// sload reads source files and dump writes them with plain open(); text mode would stop at 0x1A and rewrite line endings.
__attribute__((constructor)) static void artb_f2fs_binary_mode(void) { _set_fmode(_O_BINARY); }

int artb_f2fs_alphasort(const struct dirent **a, const struct dirent **b) { return strcmp((*a)->d_name, (*b)->d_name); }

int artb_f2fs_scandir(const char *dir, struct dirent ***names, int (*filter)(const struct dirent *), int (*compare)(const struct dirent **, const struct dirent **)) {
    DIR *handle = opendir(dir);
    if (!handle) return -1;
    struct dirent **list = NULL;
    size_t count = 0, capacity = 0;
    struct dirent *entry;
    while ((entry = readdir(handle)) != NULL) {
        if (filter && !filter(entry)) continue;
        if (count == capacity) {
            capacity = capacity ? capacity * 2 : 32;
            struct dirent **grown = realloc(list, capacity * sizeof(*list));
            if (!grown) goto fail;
            list = grown;
        }
        struct dirent *copy = malloc(sizeof(*copy));
        if (!copy) goto fail;
        memcpy(copy, entry, sizeof(*copy));
        list[count++] = copy;
    }
    closedir(handle);
    if (compare) qsort(list, count, sizeof(*list), (int (*)(const void *, const void *))compare);
    *names = list;
    return (int)count;
fail:
    while (count) free(list[--count]);
    free(list);
    closedir(handle);
    return -1;
}
#endif
