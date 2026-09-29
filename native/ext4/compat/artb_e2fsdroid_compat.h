#pragma once
#ifdef _WIN32
#include <stdio.h>
#include <sys/types.h>

ssize_t getline(char **line, size_t *size, FILE *stream);
// Provided by the erofs-tools compat layer linked through libcutils.
int asprintf(char **value, const char *format, ...);
#endif
