#include "artb_xz.h"

#include <stdlib.h>

#include "7zCrc.h"
#include "Sha256.h"
#include "Xz.h"
#include "XzCrc64.h"

struct ArtbXzDecoder {
    CXzUnpacker unpacker;
};

static void *artb_alloc(ISzAllocPtr allocator, size_t size) {
    (void)allocator;
    return malloc(size);
}

static void artb_release(ISzAllocPtr allocator, void *address) {
    (void)allocator;
    free(address);
}

static const ISzAlloc artb_allocator = {artb_alloc, artb_release};

void artb_xz_init(void) {
    CrcGenerateTable();
    Crc64GenerateTable();
    Sha256Prepare();
}

ArtbXzDecoder *artb_xz_new(void) {
    ArtbXzDecoder *decoder = (ArtbXzDecoder *)malloc(sizeof(ArtbXzDecoder));
    if (!decoder) return NULL;
    XzUnpacker_Construct(&decoder->unpacker, &artb_allocator);
    return decoder;
}

void artb_xz_free(ArtbXzDecoder *decoder) {
    if (!decoder) return;
    XzUnpacker_Free(&decoder->unpacker);
    free(decoder);
}

int artb_xz_decode(ArtbXzDecoder *decoder, const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_cap, size_t *dst_len) {
    CXzUnpacker *unpacker = &decoder->unpacker;
    SizeT out_len = dst_cap;
    SizeT in_len = src_len;
    ECoderStatus status;
    SRes res = XzUnpacker_CodeFull(unpacker, dst, &out_len, src, &in_len, CODER_FINISH_END, &status);
    // The LZMA2 coder keeps the stale dictionary address for reuse; it is replaced before any later access.
    XzUnpacker_SetOutBuf(unpacker, NULL, 0);
    // Direct output mode restarts the dictionary at every block, so multi-block input is decoded again through the streaming interface.
    if (unpacker->numTotalBlocks > 1) {
        out_len = dst_cap;
        in_len = src_len;
        XzUnpacker_Init(unpacker);
        res = XzUnpacker_Code(unpacker, dst, &out_len, src, &in_len, True, CODER_FINISH_END, &status);
    }
    *dst_len = out_len;
    if (res == SZ_ERROR_NO_ARCHIVE && unpacker->numFinishedStreams > 0) return ARTB_XZ_TRAILING;
    if (res != SZ_OK) return res;
    if (!XzUnpacker_IsStreamWasFinished(unpacker)) return ARTB_XZ_TRUNCATED;
    if (in_len != src_len) return ARTB_XZ_TRAILING;
    return ARTB_XZ_OK;
}

int artb_xz_asm_enabled(void) {
#ifdef Z7_LZMA_DEC_OPT
    return 1;
#else
    return 0;
#endif
}
