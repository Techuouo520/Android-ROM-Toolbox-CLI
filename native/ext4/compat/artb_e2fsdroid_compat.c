#include "artb_e2fsdroid_compat.h"

#include <errno.h>
#include <stdlib.h>

ssize_t getline(char **line, size_t *size, FILE *stream) {
    size_t used = 0;
    int value;
    if (!line || !size || !stream) { errno = EINVAL; return -1; }
    if (!*line || !*size) {
        *size = 128;
        *line = malloc(*size);
        if (!*line) { errno = ENOMEM; return -1; }
    }
    while ((value = fgetc(stream)) != EOF) {
        if (used + 2 > *size) {
            size_t grown = *size * 2;
            char *next = realloc(*line, grown);
            if (!next) { errno = ENOMEM; return -1; }
            *line = next;
            *size = grown;
        }
        (*line)[used++] = (char)value;
        if (value == '\n') break;
    }
    if (!used) return -1;
    (*line)[used] = 0;
    return (ssize_t)used;
}
