#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
typedef void *ArtbFile;
#define ARTB_FILE_INVALID ((ArtbFile)(intptr_t)-1)
#else
typedef int ArtbFile;
#define ARTB_FILE_INVALID (-1)
#endif

// Paths are UTF-8 with forward slashes; Windows maps them to extended-length wide paths.
ArtbFile artb_out_create(const char *path);
int artb_out_write(ArtbFile file, const void *buffer, size_t length);
int artb_out_zeros(ArtbFile file, uint64_t length);
int artb_file_close(ArtbFile file);
// Opened for positional reads, so every thread can share one image through its own handle.
ArtbFile artb_in_open(const char *path);
int artb_in_read(ArtbFile file, void *buffer, size_t length, uint64_t offset);
int artb_in_size(ArtbFile file, uint64_t *size);
int artb_make_dir(const char *path);
// Windows output uses the Cygwin symlink placeholder that artb_lstat and the image builders read back.
int artb_make_symlink(const char *target, const char *path);
int artb_make_hardlink(const char *existing, const char *path);
int artb_set_times(const char *path, int64_t seconds, uint32_t nanoseconds);
FILE *artb_open_text(const char *path);
void artb_sleep_ms(unsigned milliseconds);
// Returns a malloc'd lowercase path shared by two entries, or NULL; case-insensitive hosts would merge them.
char *artb_find_case_collision(const char *const *paths, size_t count);
#ifdef _WIN32
// Converts wmain arguments once so every path stays UTF-8 internally; returns NULL on failure.
char **artb_utf8_argv(int argc, wchar_t **wide);
#endif

#ifdef __cplusplus
}
#endif
