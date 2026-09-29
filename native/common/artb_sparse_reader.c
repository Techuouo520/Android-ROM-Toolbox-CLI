#include "artb_sparse_reader.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>
#ifndef O_BINARY
#define O_BINARY _O_BINARY
#endif
#define artb_open _open
#define artb_close _close
#define artb_read _read
#define artb_seek _lseeki64
#else
#include <unistd.h>
#define O_BINARY 0
#define artb_open open
#define artb_close close
#define artb_read read
#define artb_seek lseek
#endif
typedef struct { uint64_t start; uint64_t count; uint64_t file_offset; uint32_t fill; uint16_t type; } artb_sparse_chunk;
struct artb_sparse_reader { artb_sparse_chunk* chunks; size_t count; size_t capacity; uint64_t size; uint32_t block_size; };
static uint16_t le16(const unsigned char* p) { return (uint16_t)p[0] | ((uint16_t)p[1] << 8); }
static uint32_t le32(const unsigned char* p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static int seek_to(int fd, uint64_t offset) { if (offset > INT64_MAX) { errno = EOVERFLOW; return 0; } return artb_seek(fd, (int64_t)offset, SEEK_SET) >= 0; }
static int read_exact(int fd, void* data, size_t length) { unsigned char* p = data; while (length) { unsigned int part = length > INT_MAX ? INT_MAX : (unsigned int)length; int n = artb_read(fd, p, part); if (n <= 0) { if (n == 0) errno = EIO; return 0; } p += n; length -= (size_t)n; } return 1; }
void artb_sparse_reader_close(artb_sparse_reader* reader) { if (reader) { free(reader->chunks); free(reader); } }
uint64_t artb_sparse_reader_size(const artb_sparse_reader* reader) { return reader ? reader->size : 0; }
artb_sparse_reader* artb_sparse_reader_open(const char* path) {
    int fd = artb_open(path, O_RDONLY | O_BINARY); if (fd < 0) return NULL;
    artb_sparse_reader* reader = calloc(1, sizeof(*reader)); if (!reader) { artb_close(fd); return NULL; }
    unsigned char header[28]; int ok = read_exact(fd, header, sizeof(header));
    uint64_t file_size = 0, position = 0, blocks = 0; uint16_t file_header = 0, chunk_header = 0; uint32_t total_chunks = 0, total_blocks = 0;
    if (ok) { int64_t end = artb_seek(fd, 0, SEEK_END); if (end < 0) ok = 0; else file_size = (uint64_t)end; }
    if (ok) { file_header = le16(header + 8); chunk_header = le16(header + 10); reader->block_size = le32(header + 12); total_blocks = le32(header + 16); total_chunks = le32(header + 20); ok = le32(header) == 0xed26ff3a && le16(header + 4) == 1 && file_header >= 28 && chunk_header >= 12 && reader->block_size != 0 && (uint64_t)total_blocks * reader->block_size <= INT64_MAX && file_header <= file_size; position = file_header; }
    for (uint32_t i = 0; ok && i < total_chunks; ++i) {
        unsigned char part[12]; if (position > file_size || file_size - position < chunk_header || !seek_to(fd, position) || !read_exact(fd, part, sizeof(part))) { ok = 0; break; }
        uint16_t type = le16(part), reserved = le16(part + 2); uint32_t count = le32(part + 4), total = le32(part + 8); uint64_t payload = total >= chunk_header ? (uint64_t)total - chunk_header : UINT64_MAX;
        if (reserved != 0 || total < chunk_header || (uint64_t)total > file_size - position || blocks + count > total_blocks) { ok = 0; break; }
        if (type == 0xcac1) ok = payload == (uint64_t)count * reader->block_size;
        else if (type == 0xcac2) ok = payload == 4;
        else if (type == 0xcac4) ok = payload == 4 && count == 0;
        else if (type == 0xcac3) ok = payload == 0;
        else ok = 0;
        if (!ok) break;
        if (type != 0xcac4 && count) {
            if (reader->count == reader->capacity) { size_t next = reader->capacity ? reader->capacity * 2 : 32; if (next < reader->capacity || next > SIZE_MAX / sizeof(*reader->chunks)) { ok = 0; break; } artb_sparse_chunk* grown = realloc(reader->chunks, next * sizeof(*grown)); if (!grown) { ok = 0; break; } reader->chunks = grown; reader->capacity = next; }
            artb_sparse_chunk* chunk = &reader->chunks[reader->count++]; chunk->start = blocks; chunk->count = count; chunk->type = type; chunk->file_offset = position + chunk_header; chunk->fill = 0;
            if (type == 0xcac2 && (!seek_to(fd, chunk->file_offset) || !read_exact(fd, &chunk->fill, 4))) { ok = 0; break; }
        }
        if (type != 0xcac4) blocks += count;
        position += total;
    }
    if (blocks != total_blocks || position != file_size) ok = 0;
    artb_close(fd);
    if (!ok) { errno = EINVAL; artb_sparse_reader_close(reader); return NULL; }
    reader->size = blocks * reader->block_size; return reader;
}
int artb_sparse_reader_read(const artb_sparse_reader* reader, int private_fd, void* buffer, size_t length, uint64_t offset) {
    if (!reader || offset > reader->size || length > reader->size - offset) { errno = EINVAL; return 0; }
    unsigned char* out = buffer;
    while (length) {
        uint64_t block = offset / reader->block_size; size_t lo = 0, hi = reader->count;
        while (lo < hi) { size_t mid = lo + (hi - lo) / 2; if (reader->chunks[mid].start <= block) lo = mid + 1; else hi = mid; }
        if (!lo) { errno = EINVAL; return 0; }
        const artb_sparse_chunk* chunk = &reader->chunks[lo - 1]; if (block >= chunk->start + chunk->count) { errno = EINVAL; return 0; }
        uint64_t within = offset - chunk->start * reader->block_size; uint64_t available = chunk->count * (uint64_t)reader->block_size - within; size_t amount = length < available ? length : (size_t)available;
        if (chunk->type == 0xcac1) { if (!seek_to(private_fd, chunk->file_offset + within) || !read_exact(private_fd, out, amount)) return 0; }
        else if (chunk->type == 0xcac3) memset(out, 0, amount);
        else { const unsigned char* fill = (const unsigned char*)&chunk->fill; for (size_t i = 0; i < amount; ++i) out[i] = fill[(within + i) & 3]; }
        out += amount; offset += amount; length -= amount;
    }
    return 1;
}
