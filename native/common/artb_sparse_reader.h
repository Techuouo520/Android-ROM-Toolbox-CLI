#ifndef ARTB_SPARSE_READER_H
#define ARTB_SPARSE_READER_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct artb_sparse_reader artb_sparse_reader;
artb_sparse_reader* artb_sparse_reader_open(const char* path);
void artb_sparse_reader_close(artb_sparse_reader* reader);
uint64_t artb_sparse_reader_size(const artb_sparse_reader* reader);
int artb_sparse_reader_read(const artb_sparse_reader* reader, int private_fd, void* buffer, size_t length, uint64_t offset);
#ifdef __cplusplus
}
#endif
#endif
