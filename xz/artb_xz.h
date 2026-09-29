#ifndef ARTB_XZ_H
#define ARTB_XZ_H

#include <stddef.h>
#include <stdint.h>

#define ARTB_XZ_OK 0
#define ARTB_XZ_TRUNCATED (-1)
#define ARTB_XZ_TRAILING (-2)

typedef struct ArtbXzDecoder ArtbXzDecoder;

void artb_xz_init(void);
ArtbXzDecoder *artb_xz_new(void);
void artb_xz_free(ArtbXzDecoder *decoder);
int artb_xz_decode(ArtbXzDecoder *decoder, const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_cap, size_t *dst_len);
int artb_xz_asm_enabled(void);

#endif
