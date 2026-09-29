#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <lz4.h>
#include <zstd.h>

#include "artb_cpu.h"
#include "artb_extract_io.h"

// Offsets follow the kernel's on-disk f2fs layout; everything that scales with the block size is derived per image.
#define F2FS_MAGIC 0xF2F52010u
#define XATTR_MAGIC 0xF2F52011u
#define SUPER_OFFSET 1024
#define SUPER_SIZE 3072
#define SUPER_CRC_OFFSET 3068
#define FOOTER_SIZE 24
#define ADDR_OFFSET 360
#define EXTRA_WORDS_MAX 64
#define INLINE_XATTR_WORDS 50
#define COMPRESS_FIELDS_END 36
#define CP_BITMAP_OFFSET 192
#define NULL_ADDR 0u
#define NEW_ADDR 0xFFFFFFFFu
#define COMPRESS_ADDR 0xFFFFFFFEu
#define COMPRESS_HEADER 24
#define CHUNK_BYTES (1u << 20)
#define MAX_DEPTH 1024
#define NO_LINK SIZE_MAX
#define MODE_TYPE 0170000
#define MODE_DIR 0040000
#define MODE_REG 0100000
#define MODE_LNK 0120000

enum { FEATURE_FLEXIBLE_XATTR = 0x40, FEATURE_SB_CHECKSUM = 0x800 };
enum { INLINE_XATTR = 0x1, INLINE_DATA = 0x2, INLINE_DENTRY = 0x4, INLINE_EXTRA = 0x20 };
enum { CP_UMOUNT = 0x1, CP_COMPACT = 0x4, CP_FASTBOOT = 0x20, CP_LARGE_NAT = 0x400 };
enum { COMPR_FL = 0x4, ADVISE_ENCRYPT = 0x4 };
enum { ALG_LZO, ALG_LZ4, ALG_ZSTD, ALG_LZORLE };

static const struct {
    uint32_t mask;
    const char *name;
} feature_names[] = {{0x1, "encrypt"}, {0x2, "blkzoned"}, {0x8, "extra_attr"}, {0x10, "project_quota"}, {0x20, "inode_checksum"}, {0x40, "flexible_inline_xattr"}, {0x80, "quota"}, {0x100, "inode_crtime"}, {0x200, "lost_found"}, {0x400, "verity"}, {0x800, "sb_checksum"}, {0x1000, "casefold"}, {0x2000, "compression"}, {0x4000, "ro"}};

typedef struct {
    unsigned char super[SUPER_SIZE];
    uint32_t block_size;
    uint32_t log_blocks_per_seg;
    uint32_t blocks_per_seg;
    uint64_t block_count;
    uint32_t feature;
    uint32_t root_ino;
    uint32_t main_blkaddr;
    uint32_t inode_addrs;
    uint32_t block_addrs;
    uint32_t dentries;
    uint32_t dentry_bitmap;
    uint32_t dentry_reserved;
    uint32_t max_nid;
    uint32_t *nat;
} Fs;

typedef struct {
    const Fs *fs;
    ArtbFile file;
    unsigned char *node[3];
    unsigned char *data;
    unsigned char *xattr;
    unsigned char *packed;
    unsigned char *plain;
    size_t cluster_bytes;
    uint32_t *addrs;
    ZSTD_DCtx *zstd;
    char error[512];
} Reader;

typedef struct {
    uint32_t ino;
    uint16_t mode;
    uint8_t inline_flags;
    uint8_t advise;
    uint8_t algorithm;
    uint8_t cluster_log;
    uint32_t uid;
    uint32_t gid;
    uint32_t links;
    uint32_t xattr_nid;
    uint32_t flags;
    uint32_t extra_words;
    uint32_t xattr_words;
    uint32_t addrs;
    uint64_t size;
    int64_t mtime;
    uint32_t mtime_nsec;
} Inode;

typedef struct {
    char *path;
    uint32_t ino;
    uint16_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
    int64_t mtime;
    uint32_t mtime_nsec;
    uint64_t capabilities;
    char *label;
    char *symlink;
    size_t link_to;
} Entry;

typedef struct {
    Entry *items;
    size_t count;
    size_t capacity;
} EntryList;

typedef struct {
    char *name;
    uint32_t ino;
} Child;

typedef struct {
    Child *items;
    size_t count;
    size_t capacity;
} ChildList;

typedef struct {
    const Inode *inode;
    uint64_t remaining;
    ArtbFile out;
    unsigned char *memory;
    size_t used;
    atomic_uint_fast64_t *progress;
} DataState;

typedef struct {
    const char *image;
    const char *out_root;
    unsigned threads;
    Fs fs;
    EntryList entries;
    size_t *first_by_ino;
    unsigned char *visited;
    size_t *files;
    size_t file_count;
    atomic_size_t next_file;
    atomic_uint_fast64_t done_bytes;
    atomic_size_t done_items;
    uint64_t total_bytes;
    atomic_int failed;
    pthread_mutex_t error_lock;
    char error[1024];
} Context;

typedef int (*BlockSink)(Reader *reader, void *state, const uint32_t *addrs, uint64_t count);

static uint32_t crc_table[256];

static void crc_init(void) {
    for (uint32_t index = 0; index < 256; index++) {
        uint32_t value = index;
        for (int bit = 0; bit < 8; bit++) value = value & 1 ? (value >> 1) ^ 0xEDB88320u : value >> 1;
        crc_table[index] = value;
    }
}

// f2fs checksums are the reflected CRC32 with the caller's seed and no final inversion.
static uint32_t f2fs_crc(uint32_t crc, const unsigned char *data, size_t length) {
    while (length--) crc = crc_table[(crc ^ *data++) & 0xFF] ^ (crc >> 8);
    return crc;
}

static uint16_t le16(const unsigned char *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t le32(const unsigned char *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t le64(const unsigned char *p) { return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32; }

static void fail(Context *ctx, const char *format, ...) {
    pthread_mutex_lock(&ctx->error_lock);
    if (!atomic_load(&ctx->failed)) {
        va_list args;
        va_start(args, format);
        vsnprintf(ctx->error, sizeof(ctx->error), format, args);
        va_end(args);
        atomic_store(&ctx->failed, 1);
    }
    pthread_mutex_unlock(&ctx->error_lock);
}

static int reader_fail(Reader *reader, const char *format, ...) {
    va_list args;
    va_start(args, format);
    vsnprintf(reader->error, sizeof(reader->error), format, args);
    va_end(args);
    return -1;
}

static char *copy_string(const char *value, size_t length) {
    char *copy = malloc(length + 1);
    if (!copy) return NULL;
    memcpy(copy, value, length);
    copy[length] = 0;
    return copy;
}

static char *join_path(const char *left, const char *right) {
    size_t a = strlen(left), b = strlen(right);
    char *joined = malloc(a + b + 1);
    if (!joined) return NULL;
    memcpy(joined, left, a);
    memcpy(joined + a, right, b + 1);
    return joined;
}

static int reader_open(Reader *reader, const Fs *fs, const char *image) {
    memset(reader, 0, sizeof(*reader));
    reader->fs = fs;
    reader->file = artb_in_open(image);
    if (reader->file == ARTB_FILE_INVALID) return reader_fail(reader, "open %s failed", image);
    return 0;
}

// Buffers depend on the block size, so they are sized once the superblock is known.
static int reader_buffers(Reader *reader) {
    const Fs *fs = reader->fs;
    for (int level = 0; level < 3; level++) reader->node[level] = malloc(fs->block_size);
    reader->data = malloc(CHUNK_BYTES > fs->block_size ? CHUNK_BYTES : fs->block_size);
    reader->xattr = malloc(2 * (size_t)fs->block_size);
    reader->addrs = malloc(sizeof(uint32_t) * (fs->inode_addrs > fs->block_addrs ? fs->inode_addrs : fs->block_addrs));
    if (!reader->node[0] || !reader->node[1] || !reader->node[2] || !reader->data || !reader->xattr || !reader->addrs) return reader_fail(reader, "out of memory");
    return 0;
}

static void reader_close(Reader *reader) {
    if (reader->file != ARTB_FILE_INVALID && reader->fs) artb_file_close(reader->file);
    for (int level = 0; level < 3; level++) free(reader->node[level]);
    free(reader->data);
    free(reader->xattr);
    free(reader->packed);
    free(reader->plain);
    free(reader->addrs);
    ZSTD_freeDCtx(reader->zstd);
}

static bool data_addr(const Fs *fs, uint32_t addr) { return addr >= fs->main_blkaddr && addr < fs->block_count; }

static int read_blocks(Reader *reader, uint64_t block, uint32_t count, unsigned char *buffer) {
    const Fs *fs = reader->fs;
    if (block + count > fs->block_count) return reader_fail(reader, "block %" PRIu64 " lies beyond the filesystem", block);
    if (artb_in_read(reader->file, buffer, (size_t)count * fs->block_size, block * fs->block_size)) return reader_fail(reader, "read block %" PRIu64 " failed", block);
    return 0;
}

static int read_node(Reader *reader, uint32_t nid, unsigned char *buffer) {
    const Fs *fs = reader->fs;
    if (!nid || nid >= fs->max_nid) return reader_fail(reader, "node %u is out of range", nid);
    uint32_t addr = fs->nat[nid];
    if (!data_addr(fs, addr)) return reader_fail(reader, "node %u has no valid block (0x%x)", nid, addr);
    if (read_blocks(reader, addr, 1, buffer)) return -1;
    if (le32(buffer + fs->block_size - FOOTER_SIZE) != nid) return reader_fail(reader, "block 0x%x does not hold node %u", addr, nid);
    return 0;
}

static int parse_inode(Reader *reader, uint32_t ino, const unsigned char *raw, Inode *inode) {
    const Fs *fs = reader->fs;
    memset(inode, 0, sizeof(*inode));
    inode->ino = ino;
    if (le32(raw + fs->block_size - FOOTER_SIZE + 4) != ino) return reader_fail(reader, "node %u is not an inode", ino);
    inode->mode = le16(raw);
    inode->advise = raw[2];
    inode->inline_flags = raw[3];
    inode->uid = le32(raw + 4);
    inode->gid = le32(raw + 8);
    inode->links = le32(raw + 12);
    inode->size = le64(raw + 16);
    inode->mtime = (int64_t)le64(raw + 48);
    inode->mtime_nsec = le32(raw + 64);
    inode->xattr_nid = le32(raw + 76);
    inode->flags = le32(raw + 80);
    if (inode->inline_flags & INLINE_EXTRA) {
        uint16_t extra = le16(raw + ADDR_OFFSET);
        if (extra % 4 || extra / 4 > EXTRA_WORDS_MAX) return reader_fail(reader, "inode %u has invalid extra size %u", ino, extra);
        inode->extra_words = extra / 4u;
    }
    // Matches the kernel: flexible images store the size, older ones reserve 200 bytes for inline xattrs and dentries.
    if (fs->feature & FEATURE_FLEXIBLE_XATTR) inode->xattr_words = inode->extra_words ? le16(raw + ADDR_OFFSET + 2) : 0;
    else if (inode->inline_flags & (INLINE_XATTR | INLINE_DENTRY)) inode->xattr_words = INLINE_XATTR_WORDS;
    if (inode->extra_words + inode->xattr_words + 1 >= fs->inode_addrs) return reader_fail(reader, "inode %u has an invalid inline layout", ino);
    inode->addrs = fs->inode_addrs - inode->extra_words - inode->xattr_words;
    if ((inode->mode & MODE_TYPE) == MODE_REG && (inode->flags & COMPR_FL)) {
        if (inode->extra_words * 4 < COMPRESS_FIELDS_END) return reader_fail(reader, "compressed inode %u lacks compression fields", ino);
        inode->algorithm = raw[392];
        inode->cluster_log = raw[393];
        if (inode->cluster_log < 2 || inode->cluster_log > 8) return reader_fail(reader, "inode %u has invalid cluster size", ino);
        inode->addrs &= ~((1u << inode->cluster_log) - 1);
    }
    return 0;
}

static bool compressed(const Inode *inode) { return (inode->mode & MODE_TYPE) == MODE_REG && (inode->flags & COMPR_FL); }

static uint32_t block_addrs_of(const Fs *fs, const Inode *inode) { return compressed(inode) ? fs->block_addrs & ~((1u << inode->cluster_log) - 1) : fs->block_addrs; }

static uint32_t inline_capacity(const Fs *fs, const Inode *inode) { return 4 * (fs->inode_addrs - inode->xattr_words - inode->extra_words - 1); }

static const unsigned char *inline_base(const unsigned char *raw, const Inode *inode) { return raw + ADDR_OFFSET + 4 * (inode->extra_words + 1); }

static int walk_node(Reader *reader, uint32_t nid, int depth, uint32_t per_block, uint64_t *done, uint64_t total, BlockSink sink, void *state) {
    const Fs *fs = reader->fs;
    uint64_t span = per_block;
    for (int level = 0; level < depth; level++) span *= fs->block_addrs;
    uint64_t take = total - *done < span ? total - *done : span;
    if (!take) return 0;
    if (!nid) {
        *done += take;
        return sink(reader, state, NULL, take);
    }
    unsigned char *buffer = reader->node[depth];
    if (read_node(reader, nid, buffer)) return -1;
    if (!depth) {
        for (uint64_t index = 0; index < take; index++) reader->addrs[index] = le32(buffer + 4 * index);
        *done += take;
        return sink(reader, state, reader->addrs, take);
    }
    for (uint32_t index = 0; index < fs->block_addrs && *done < total; index++) {
        if (walk_node(reader, le32(buffer + 4 * index), depth - 1, per_block, done, total, sink, state)) return -1;
    }
    return 0;
}

// Hands block addresses to sink in file order: inode slots, two direct, two indirect and one double indirect node.
static int walk_blocks(Reader *reader, const unsigned char *raw, const Inode *inode, uint64_t total, BlockSink sink, void *state) {
    const Fs *fs = reader->fs;
    uint32_t per_block = block_addrs_of(fs, inode);
    uint64_t limit = inode->addrs + 2 * (uint64_t)per_block + 2 * (uint64_t)per_block * fs->block_addrs + (uint64_t)per_block * fs->block_addrs * fs->block_addrs;
    if (total > limit) return reader_fail(reader, "inode %u is larger than its block map", inode->ino);
    uint64_t done = inode->addrs < total ? inode->addrs : total;
    for (uint64_t index = 0; index < done; index++) reader->addrs[index] = le32(raw + ADDR_OFFSET + 4 * (inode->extra_words + index));
    if (done && sink(reader, state, reader->addrs, done)) return -1;
    static const int depths[5] = {0, 0, 1, 1, 2};
    const unsigned char *nids = raw + fs->block_size - FOOTER_SIZE - 20;
    for (int index = 0; index < 5 && done < total; index++) {
        if (walk_node(reader, le32(nids + 4 * index), depths[index], per_block, &done, total, sink, state)) return -1;
    }
    return 0;
}

static int produce(Reader *reader, DataState *state, const unsigned char *bytes, uint64_t length) {
    if (length > state->remaining) length = state->remaining;
    if (!length) return 0;
    if (state->memory) {
        if (bytes) memcpy(state->memory + state->used, bytes, (size_t)length);
        else memset(state->memory + state->used, 0, (size_t)length);
        state->used += (size_t)length;
    } else if (bytes ? artb_out_write(state->out, bytes, (size_t)length) : artb_out_zeros(state->out, length)) {
        return reader_fail(reader, "write failed: %s", strerror(errno));
    }
    state->remaining -= length;
    if (state->progress) atomic_fetch_add(state->progress, length);
    return 0;
}

static int plain_sink(Reader *reader, void *opaque, const uint32_t *addrs, uint64_t count) {
    DataState *state = opaque;
    const Fs *fs = reader->fs;
    uint32_t block_size = fs->block_size, max_run = CHUNK_BYTES / block_size ? CHUNK_BYTES / block_size : 1;
    if (!addrs) return produce(reader, state, NULL, count * block_size);
    for (uint64_t index = 0; index < count && state->remaining;) {
        uint32_t addr = addrs[index];
        if (addr == NULL_ADDR || addr == NEW_ADDR) {
            if (produce(reader, state, NULL, block_size)) return -1;
            index++;
            continue;
        }
        if (!data_addr(fs, addr)) return reader_fail(reader, "inode %u points at invalid block 0x%x", state->inode->ino, addr);
        uint64_t needed = (state->remaining + block_size - 1) / block_size;
        uint32_t run = 1;
        while (index + run < count && run < max_run && run < needed && addrs[index + run] == addr + run) run++;
        if (read_blocks(reader, addr, run, reader->data) || produce(reader, state, reader->data, (uint64_t)run * block_size)) return -1;
        index += run;
    }
    return 0;
}

static int decompress_cluster(Reader *reader, DataState *state, const uint32_t *addrs, uint32_t cluster) {
    const Fs *fs = reader->fs;
    const Inode *inode = state->inode;
    size_t bytes = (size_t)cluster * fs->block_size;
    if (reader->cluster_bytes < bytes) {
        free(reader->packed);
        free(reader->plain);
        reader->packed = malloc(bytes);
        reader->plain = malloc(bytes);
        reader->cluster_bytes = reader->packed && reader->plain ? bytes : 0;
        if (!reader->cluster_bytes) return reader_fail(reader, "out of memory");
    }
    if (!data_addr(fs, addrs[1]) || read_blocks(reader, addrs[1], 1, reader->packed)) return reader_fail(reader, "inode %u has an unreadable compressed cluster", inode->ino);
    uint32_t length = le32(reader->packed);
    uint64_t blocks = ((uint64_t)COMPRESS_HEADER + length + fs->block_size - 1) / fs->block_size;
    if (!length || blocks > cluster - 1) return reader_fail(reader, "inode %u has a corrupt compressed cluster", inode->ino);
    for (uint32_t index = 1; index < blocks;) {
        uint32_t addr = addrs[1 + index], run = 1;
        if (!data_addr(fs, addr)) return reader_fail(reader, "inode %u points at invalid block 0x%x", inode->ino, addr);
        while (index + run < blocks && addrs[1 + index + run] == addr + run) run++;
        if (read_blocks(reader, addr, run, reader->packed + (size_t)index * fs->block_size)) return -1;
        index += run;
    }
    size_t produced = 0;
    if (inode->algorithm == ALG_LZ4) {
        int result = LZ4_decompress_safe((const char *)reader->packed + COMPRESS_HEADER, (char *)reader->plain, (int)length, (int)bytes);
        produced = result < 0 ? 0 : (size_t)result;
    } else if (inode->algorithm == ALG_ZSTD) {
        if (!reader->zstd && !(reader->zstd = ZSTD_createDCtx())) return reader_fail(reader, "out of memory");
        size_t result = ZSTD_decompressDCtx(reader->zstd, reader->plain, bytes, reader->packed + COMPRESS_HEADER, length);
        produced = ZSTD_isError(result) ? 0 : result;
    }
    // The kernel always compresses whole clusters, so anything shorter is corruption.
    if (produced != bytes) return reader_fail(reader, "inode %u has a cluster that does not decompress", inode->ino);
    return produce(reader, state, reader->plain, bytes);
}

static int compressed_sink(Reader *reader, void *opaque, const uint32_t *addrs, uint64_t count) {
    DataState *state = opaque;
    uint32_t cluster = 1u << state->inode->cluster_log;
    if (!addrs) return produce(reader, state, NULL, count * reader->fs->block_size);
    for (uint64_t base = 0; base < count && state->remaining; base += cluster) {
        uint32_t length = count - base < cluster ? (uint32_t)(count - base) : cluster;
        if (addrs[base] != COMPRESS_ADDR) {
            if (plain_sink(reader, opaque, addrs + base, length)) return -1;
        } else if (length != cluster || decompress_cluster(reader, state, addrs + base, cluster)) {
            return length != cluster ? reader_fail(reader, "inode %u has a split compressed cluster", state->inode->ino) : -1;
        }
    }
    return 0;
}

static int read_data(Reader *reader, const unsigned char *raw, const Inode *inode, DataState *state) {
    const Fs *fs = reader->fs;
    state->inode = inode;
    state->remaining = inode->size;
    if (inode->inline_flags & INLINE_DATA) {
        if (inode->size > inline_capacity(fs, inode)) return reader_fail(reader, "inode %u has oversized inline data", inode->ino);
        return produce(reader, state, inline_base(raw, inode), inode->size);
    }
    uint64_t total = (inode->size + fs->block_size - 1) / fs->block_size;
    if (!compressed(inode)) return walk_blocks(reader, raw, inode, total, plain_sink, state);
    if (inode->algorithm != ALG_LZ4 && inode->algorithm != ALG_ZSTD) return reader_fail(reader, "inode %u uses %s compression, which is not supported", inode->ino, inode->algorithm == ALG_LZO || inode->algorithm == ALG_LZORLE ? "LZO" : "unknown");
    uint64_t cluster = 1u << inode->cluster_log;
    return walk_blocks(reader, raw, inode, (total + cluster - 1) / cluster * cluster, compressed_sink, state);
}

static int child_push(ChildList *list, const unsigned char *name, size_t length, uint32_t ino) {
    if (list->count == list->capacity) {
        size_t capacity = list->capacity ? list->capacity * 2 : 64;
        Child *items = realloc(list->items, capacity * sizeof(Child));
        if (!items) return -1;
        list->items = items;
        list->capacity = capacity;
    }
    char *copy = copy_string((const char *)name, length);
    if (!copy) return -1;
    list->items[list->count++] = (Child){copy, ino};
    return 0;
}

static int parse_dentries(Reader *reader, ChildList *list, const unsigned char *bitmap, const unsigned char *dentries, const unsigned char *names, uint32_t slots) {
    for (uint32_t position = 0; position < slots;) {
        if (!(bitmap[position >> 3] & (1u << (position & 7)))) {
            position++;
            continue;
        }
        const unsigned char *dentry = dentries + 11 * (size_t)position;
        uint32_t ino = le32(dentry + 4);
        uint16_t length = le16(dentry + 8);
        if (!length) {
            position++;
            continue;
        }
        uint32_t used = (length + 7u) / 8u;
        if (length > 255 || position + used > slots) return reader_fail(reader, "corrupt directory entry");
        const unsigned char *name = names + 8 * (size_t)position;
        bool dots = (length == 1 && name[0] == '.') || (length == 2 && name[0] == '.' && name[1] == '.');
        if (!dots) {
            if (memchr(name, '/', length) || memchr(name, 0, length)) return reader_fail(reader, "directory entry has an invalid name");
            if (child_push(list, name, length, ino)) return reader_fail(reader, "out of memory");
        }
        position += used;
    }
    return 0;
}

static int dentry_sink(Reader *reader, void *opaque, const uint32_t *addrs, uint64_t count) {
    const Fs *fs = reader->fs;
    if (!addrs) return 0;
    for (uint64_t index = 0; index < count; index++) {
        uint32_t addr = addrs[index];
        if (addr == NULL_ADDR || addr == NEW_ADDR) continue;
        if (!data_addr(fs, addr)) return reader_fail(reader, "directory points at invalid block 0x%x", addr);
        if (read_blocks(reader, addr, 1, reader->data)) return -1;
        const unsigned char *dentries = reader->data + fs->dentry_bitmap + fs->dentry_reserved;
        if (parse_dentries(reader, opaque, reader->data, dentries, dentries + 11 * (size_t)fs->dentries, fs->dentries)) return -1;
    }
    return 0;
}

static int list_children(Reader *reader, const unsigned char *raw, const Inode *inode, ChildList *list) {
    const Fs *fs = reader->fs;
    if (inode->inline_flags & INLINE_DENTRY) {
        uint32_t capacity = inline_capacity(fs, inode), slots = capacity * 8 / (19 * 8 + 1), bitmap = (slots + 7) / 8;
        const unsigned char *base = inline_base(raw, inode), *dentries = base + capacity - 19 * slots;
        if (capacity < 19 * slots + bitmap) return reader_fail(reader, "inode %u has an invalid inline directory", inode->ino);
        return parse_dentries(reader, list, base, dentries, dentries + 11 * (size_t)slots, slots);
    }
    return walk_blocks(reader, raw, inode, (inode->size + fs->block_size - 1) / fs->block_size, dentry_sink, list);
}

static uint64_t parse_capabilities(const unsigned char *data, size_t length) {
    uint32_t magic = length >= 4 ? le32(data) : 0, revision = magic & 0xFF000000u;
    if (revision == 0x01000000u && length == 12) return le32(data + 4);
    if ((revision == 0x02000000u || revision == 0x03000000u) && (length == 20 || length == 24)) return (uint64_t)le32(data + 4) | (uint64_t)le32(data + 12) << 32;
    return 0;
}

// Android keeps SELinux labels with a trailing NUL and file capabilities as vfs_cap_data under the security index.
static int read_security(Reader *reader, const unsigned char *raw, const Inode *inode, Entry *entry) {
    const Fs *fs = reader->fs;
    size_t inline_size = (inode->inline_flags & INLINE_XATTR) ? 4 * (size_t)inode->xattr_words : 0;
    size_t block_size = inode->xattr_nid ? fs->block_size - FOOTER_SIZE : 0, total = inline_size + block_size;
    if (!total) return 0;
    memcpy(reader->xattr, raw + ADDR_OFFSET + 4 * (size_t)(fs->inode_addrs - inode->xattr_words), inline_size);
    if (block_size) {
        if (read_node(reader, inode->xattr_nid, reader->node[0])) return -1;
        memcpy(reader->xattr + inline_size, reader->node[0], block_size);
    }
    if (total < 24 || le32(reader->xattr) != XATTR_MAGIC) return 0;
    for (size_t offset = 24; offset + 4 <= total;) {
        const unsigned char *item = reader->xattr + offset;
        if (!le32(item)) break;
        size_t name_length = item[1], value_length = le16(item + 2), size = (4 + name_length + value_length + 3) & ~(size_t)3;
        if (offset + size > total) return reader_fail(reader, "inode %u has corrupt xattrs", inode->ino);
        const char *name = (const char *)item + 4;
        const unsigned char *value = item + 4 + name_length;
        if (item[0] == 6 && name_length == 7 && !memcmp(name, "selinux", 7)) {
            while (value_length && !value[value_length - 1]) value_length--;
            free(entry->label);
            if (!(entry->label = copy_string((const char *)value, value_length))) return reader_fail(reader, "out of memory");
        } else if (item[0] == 6 && name_length == 10 && !memcmp(name, "capability", 10)) {
            entry->capabilities = parse_capabilities(value, value_length);
        }
        offset += size;
    }
    return 0;
}

static int entry_push(EntryList *list, const Entry *entry) {
    if (list->count == list->capacity) {
        size_t capacity = list->capacity ? list->capacity * 2 : 1024;
        Entry *items = realloc(list->items, capacity * sizeof(Entry));
        if (!items) return -1;
        list->items = items;
        list->capacity = capacity;
    }
    list->items[list->count++] = *entry;
    return 0;
}

static int compare_children(const void *left, const void *right) { return strcmp(((const Child *)left)->name, ((const Child *)right)->name); }

static int describe(Context *ctx, Reader *reader, const unsigned char *raw, const Inode *inode, char *path, Entry *entry) {
    *entry = (Entry){path, inode->ino, inode->mode, inode->uid, inode->gid, inode->size, inode->mtime, inode->mtime_nsec, 0, NULL, NULL, NO_LINK};
    if (inode->advise & ADVISE_ENCRYPT) return reader_fail(reader, "%s is encrypted", path);
    if (read_security(reader, raw, inode, entry)) return -1;
    if ((inode->mode & MODE_TYPE) == MODE_LNK) {
        if (inode->size > 65536) return reader_fail(reader, "%s has an oversized symlink target", path);
        DataState state = {0};
        if (!(state.memory = calloc(1, (size_t)inode->size + 1))) return reader_fail(reader, "out of memory");
        if (read_data(reader, raw, inode, &state)) {
            free(state.memory);
            return -1;
        }
        entry->symlink = (char *)state.memory;
    }
    if ((inode->mode & MODE_TYPE) == MODE_REG && inode->links > 1) {
        if (ctx->first_by_ino[inode->ino] != NO_LINK) entry->link_to = ctx->first_by_ino[inode->ino];
        else ctx->first_by_ino[inode->ino] = ctx->entries.count;
    }
    return 0;
}

static int walk_dir(Context *ctx, Reader *reader, const unsigned char *raw, const Inode *dir, const char *parent, unsigned depth) {
    const Fs *fs = &ctx->fs;
    if (depth > MAX_DEPTH) return reader_fail(reader, "directory tree under %s is too deep", parent);
    ChildList children = {0};
    int result = list_children(reader, raw, dir, &children);
    if (result) {
        char detail[512];
        snprintf(detail, sizeof(detail), "%.240s: %.240s", parent, reader->error);
        memcpy(reader->error, detail, strlen(detail) + 1);
    } else {
        qsort(children.items, children.count, sizeof(Child), compare_children);
    }
    unsigned char *child_raw = result ? NULL : malloc(fs->block_size);
    if (!result && !child_raw) result = reader_fail(reader, "out of memory");
    for (size_t index = 0; !result && index < children.count; index++) {
        const Child *child = &children.items[index];
        char *prefix = join_path(strcmp(parent, "/") ? parent : "", "/");
        char *path = prefix ? join_path(prefix, child->name) : NULL;
        free(prefix);
        if (!path) {
            result = reader_fail(reader, "out of memory");
            break;
        }
        Inode inode;
        Entry entry;
        if (read_node(reader, child->ino, child_raw) || parse_inode(reader, child->ino, child_raw, &inode) || describe(ctx, reader, child_raw, &inode, path, &entry)) {
            char detail[512];
            snprintf(detail, sizeof(detail), "%.240s: %.240s", path, reader->error);
            memcpy(reader->error, detail, strlen(detail) + 1);
            free(path);
            result = -1;
            break;
        }
        if (entry_push(&ctx->entries, &entry)) {
            result = reader_fail(reader, "out of memory");
            break;
        }
        if ((inode.mode & MODE_TYPE) == MODE_DIR) {
            if (ctx->visited[inode.ino >> 3] & (1u << (inode.ino & 7))) {
                result = reader_fail(reader, "%s loops back to an earlier directory", path);
                break;
            }
            ctx->visited[inode.ino >> 3] |= (unsigned char)(1u << (inode.ino & 7));
            result = walk_dir(ctx, reader, child_raw, &inode, path, depth + 1);
        }
    }
    for (size_t index = 0; index < children.count; index++) free(children.items[index].name);
    free(children.items);
    free(child_raw);
    return result;
}

static bool check_super(const unsigned char *super) {
    if (le32(super) != F2FS_MAGIC) return false;
    if (le32(super + 2180) & FEATURE_SB_CHECKSUM) {
        uint32_t offset = le32(super + 32);
        if (offset != SUPER_CRC_OFFSET || f2fs_crc(F2FS_MAGIC, super, offset) != le32(super + offset)) return false;
    }
    return true;
}

static int load_super(Reader *reader, Fs *fs) {
    static const uint64_t offsets[] = {SUPER_OFFSET, 4096 + SUPER_OFFSET, 16384 + SUPER_OFFSET};
    bool found = false;
    for (size_t index = 0; index < sizeof(offsets) / sizeof(offsets[0]) && !found; index++) {
        if (artb_in_read(reader->file, fs->super, SUPER_SIZE, offsets[index]) || !check_super(fs->super)) continue;
        uint32_t log_block = le32(fs->super + 16);
        found = log_block >= 12 && log_block <= 14 && (index == 0 || offsets[index] == (1ull << log_block) + SUPER_OFFSET);
    }
    if (!found) return reader_fail(reader, "no valid F2FS superblock");
    const unsigned char *super = fs->super;
    fs->block_size = 1u << le32(super + 16);
    fs->log_blocks_per_seg = le32(super + 20);
    fs->block_count = le64(super + 36);
    fs->main_blkaddr = le32(super + 92);
    fs->root_ino = le32(super + 96);
    fs->feature = le32(super + 2180);
    if (fs->log_blocks_per_seg < 4 || fs->log_blocks_per_seg > 12) return reader_fail(reader, "unsupported segment size");
    fs->blocks_per_seg = 1u << fs->log_blocks_per_seg;
    if (super[2201]) return reader_fail(reader, "multi-device F2FS images are not supported");
    if (le32(super + 76) >= fs->main_blkaddr || le32(super + 84) >= fs->main_blkaddr || fs->main_blkaddr >= fs->block_count) return reader_fail(reader, "superblock layout is inconsistent");
    fs->inode_addrs = (fs->block_size - ADDR_OFFSET - 20 - FOOTER_SIZE) / 4;
    fs->block_addrs = (fs->block_size - FOOTER_SIZE) / 4;
    fs->dentries = 8 * fs->block_size / (19 * 8 + 1);
    fs->dentry_bitmap = (fs->dentries + 7) / 8;
    fs->dentry_reserved = fs->block_size - (19 * fs->dentries + fs->dentry_bitmap);
    return 0;
}

static bool check_cp_block(const Fs *fs, const unsigned char *block) {
    uint32_t offset = le32(block + 164);
    if (offset < CP_BITMAP_OFFSET || offset > fs->block_size - 4) return false;
    uint32_t crc = f2fs_crc(F2FS_MAGIC, block, offset);
    if (offset < fs->block_size - 4) crc = f2fs_crc(crc, block + offset + 4, fs->block_size - offset - 4);
    return crc == le32(block + offset);
}

static bool load_pack(Reader *reader, uint64_t start, unsigned char *first, unsigned char *last, uint64_t *version) {
    const Fs *fs = reader->fs;
    if (read_blocks(reader, start, 1, first) || !check_cp_block(fs, first)) return false;
    uint32_t total = le32(first + 136);
    if (total < 2 || total > fs->blocks_per_seg) return false;
    if (read_blocks(reader, start + total - 1, 1, last) || !check_cp_block(fs, last) || le64(first) != le64(last)) return false;
    *version = le64(first);
    return true;
}

// Picks the newer valid checkpoint pack, then builds a flat nid-to-block table from the NAT copies it selects and the NAT journal.
static int load_nat(Reader *reader, Fs *fs) {
    const unsigned char *super = fs->super;
    uint32_t cp_blkaddr = le32(super + 76), nat_blkaddr = le32(super + 84), nat_segments = le32(super + 60), payload = le32(super + 1664);
    size_t block_size = fs->block_size;
    unsigned char *first = malloc(block_size), *last = malloc(block_size), *checkpoint = NULL, *buffer = NULL;
    uint64_t version_one = 0, version_two = 0;
    int result = -1;
    if (!first || !last) {
        reader_fail(reader, "out of memory");
        goto done;
    }
    bool one = load_pack(reader, cp_blkaddr, first, last, &version_one), two = load_pack(reader, cp_blkaddr + fs->blocks_per_seg, first, last, &version_two);
    if (!one && !two) {
        reader_fail(reader, "no valid checkpoint");
        goto done;
    }
    uint64_t start = cp_blkaddr + (two && (!one || (int64_t)(version_two - version_one) > 0) ? fs->blocks_per_seg : 0);
    if (payload > fs->blocks_per_seg || !(checkpoint = malloc((1 + (size_t)payload) * block_size)) || read_blocks(reader, start, 1 + payload, checkpoint)) {
        if (!reader->error[0]) reader_fail(reader, "cannot read the checkpoint");
        goto done;
    }
    uint32_t flags = le32(checkpoint + 132), bitmap_bytes = le32(checkpoint + 160), total = le32(checkpoint + 136);
    size_t bitmap_offset = CP_BITMAP_OFFSET;
    if (flags & CP_LARGE_NAT) bitmap_offset += 4;
    else if (!payload) bitmap_offset += le32(checkpoint + 156);
    uint64_t nat_blocks = (uint64_t)(nat_segments / 2) << fs->log_blocks_per_seg;
    if (!nat_segments || bitmap_offset + bitmap_bytes > (1 + (size_t)payload) * block_size || (uint64_t)bitmap_bytes * 8 < nat_blocks || nat_blocks * (block_size / 9) >= UINT32_MAX) {
        reader_fail(reader, "checkpoint NAT bitmap is inconsistent");
        goto done;
    }
    const unsigned char *bitmap = checkpoint + bitmap_offset;
    uint32_t entries = (uint32_t)(block_size / 9);
    fs->max_nid = (uint32_t)(nat_blocks * entries);
    fs->nat = calloc(fs->max_nid, sizeof(uint32_t));
    buffer = malloc(2 * (size_t)fs->blocks_per_seg * block_size);
    if (!fs->nat || !buffer) {
        reader_fail(reader, "out of memory");
        goto done;
    }
    for (uint32_t segment = 0; segment < nat_segments / 2; segment++) {
        if (read_blocks(reader, nat_blkaddr + ((uint64_t)segment << fs->log_blocks_per_seg << 1), 2 * fs->blocks_per_seg, buffer)) goto done;
        for (uint32_t index = 0; index < fs->blocks_per_seg; index++) {
            uint64_t block = ((uint64_t)segment << fs->log_blocks_per_seg) + index;
            bool second = bitmap[block >> 3] & (0x80u >> (block & 7));
            const unsigned char *source = buffer + ((second ? fs->blocks_per_seg : 0) + (size_t)index) * block_size;
            for (uint32_t entry = 0; entry < entries; entry++) fs->nat[block * entries + entry] = le32(source + 9 * (size_t)entry + 5);
        }
    }
    uint64_t summary = flags & CP_COMPACT ? start + le32(checkpoint + 140) : start + total - ((flags & (CP_UMOUNT | CP_FASTBOOT)) ? 7 : 4);
    if (read_blocks(reader, summary, 1, buffer)) goto done;
    size_t journal_size = block_size - 5 - 7 * block_size / 8;
    const unsigned char *journal = flags & CP_COMPACT ? buffer : buffer + 7 * block_size / 8;
    uint16_t count = le16(journal);
    if (count > (journal_size - 2) / 13) {
        reader_fail(reader, "NAT journal is corrupt");
        goto done;
    }
    for (uint16_t index = 0; index < count; index++) {
        const unsigned char *item = journal + 2 + 13 * (size_t)index;
        uint32_t nid = le32(item);
        if (nid < fs->max_nid) fs->nat[nid] = le32(item + 9);
    }
    result = 0;
done:
    free(first);
    free(last);
    free(checkpoint);
    free(buffer);
    return result;
}

static char *out_path(Context *ctx, const Entry *entry) { return join_path(ctx->out_root, strcmp(entry->path, "/") ? entry->path : ""); }

static int extract_file(Context *ctx, Reader *reader, const Entry *entry, unsigned char *raw) {
    Inode inode;
    if (read_node(reader, entry->ino, raw) || parse_inode(reader, entry->ino, raw, &inode)) return -1;
    char *path = out_path(ctx, entry);
    if (!path) return reader_fail(reader, "out of memory");
    DataState state = {0};
    state.progress = &ctx->done_bytes;
    state.out = artb_out_create(path);
    if (state.out == ARTB_FILE_INVALID) {
        free(path);
        return reader_fail(reader, "create failed");
    }
    int result = read_data(reader, raw, &inode, &state);
    if (artb_file_close(state.out) && !result) result = reader_fail(reader, "close failed");
    if (!result && artb_set_times(path, entry->mtime, entry->mtime_nsec)) result = reader_fail(reader, "set times failed");
    free(path);
    return result;
}

static void *file_worker(void *argument) {
    Context *ctx = argument;
    Reader reader;
    unsigned char *raw = NULL;
    if (reader_open(&reader, &ctx->fs, ctx->image) || reader_buffers(&reader) || !(raw = malloc(ctx->fs.block_size))) {
        fail(ctx, "%s", reader.error[0] ? reader.error : "out of memory");
        reader_close(&reader);
        return NULL;
    }
    while (!atomic_load(&ctx->failed)) {
        size_t index = atomic_fetch_add(&ctx->next_file, 1);
        if (index >= ctx->file_count) break;
        const Entry *entry = &ctx->entries.items[ctx->files[index]];
        if (extract_file(ctx, &reader, entry, raw)) {
            fail(ctx, "extract %s: %s", entry->path, reader.error);
            break;
        }
        atomic_fetch_add(&ctx->done_items, 1);
    }
    free(raw);
    reader_close(&reader);
    return NULL;
}

static void report_progress(Context *ctx) {
    printf("progress %" PRIu64 " %" PRIu64 " %zu %zu\n", (uint64_t)atomic_load(&ctx->done_bytes), ctx->total_bytes, atomic_load(&ctx->done_items), ctx->entries.count);
    fflush(stdout);
}

typedef struct {
    Context *ctx;
    atomic_int stop;
} Reporter;

static void *progress_worker(void *argument) {
    Reporter *reporter = argument;
    while (!atomic_load(&reporter->stop)) {
        report_progress(reporter->ctx);
        for (int step = 0; step < 10 && !atomic_load(&reporter->stop); step++) artb_sleep_ms(10);
    }
    return NULL;
}

static void escape_path(FILE *out, const char *path) {
    for (const char *cursor = path; *cursor; cursor++) {
        if (strchr(".+[]*", *cursor)) fputc('\\', out);
        fputc(*cursor, out);
    }
}

static void write_utf8(FILE *out, uint32_t code) {
    if (code < 0x80) fputc((int)code, out);
    else if (code < 0x800) fprintf(out, "%c%c", 0xC0 | (code >> 6), 0x80 | (code & 0x3F));
    else if (code < 0x10000) fprintf(out, "%c%c%c", 0xE0 | (code >> 12), 0x80 | ((code >> 6) & 0x3F), 0x80 | (code & 0x3F));
    else fprintf(out, "%c%c%c%c", 0xF0 | (code >> 18), 0x80 | ((code >> 12) & 0x3F), 0x80 | ((code >> 6) & 0x3F), 0x80 | (code & 0x3F));
}

// The volume name is UTF-16LE, up to 512 code units.
static void write_label(FILE *out, const unsigned char *name) {
    for (size_t index = 0; index < 512; index++) {
        uint32_t unit = le16(name + 2 * index);
        if (!unit) break;
        if (unit >= 0xD800 && unit < 0xDC00 && index + 1 < 512) {
            uint32_t low = le16(name + 2 * (index + 1));
            if (low >= 0xDC00 && low < 0xE000) {
                write_utf8(out, 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00));
                index++;
                continue;
            }
        }
        write_utf8(out, unit);
    }
}

static void write_options(Context *ctx, FILE *out, const Entry *root) {
    const Fs *fs = &ctx->fs;
    const unsigned char *super = fs->super, *uuid = super + 108;
    char uuid_text[40], features[512] = "", version[257];
    snprintf(uuid_text, sizeof(uuid_text), "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7], uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
    for (size_t index = 0; index < sizeof(feature_names) / sizeof(feature_names[0]); index++) {
        if (!(fs->feature & feature_names[index].mask)) continue;
        if (*features) strncat(features, ",", sizeof(features) - strlen(features) - 1);
        strncat(features, feature_names[index].name, sizeof(features) - strlen(features) - 1);
    }
    memcpy(version, super + 1668, 252);
    version[252] = 0;
    fputs("Filesystem volume name: ", out);
    write_label(out, super + 124);
    fprintf(out, "\nFilesystem UUID:        %s\nFilesystem features:    %s\nFilesystem version:     %s\nBlock size:             %u\nBlock count:            %" PRIu64 "\nSegments per section:   %u\nSections per zone:      %u\nRoot owner:             %u:%u\nTimestamp:              %" PRId64 "\n", uuid_text, features, version, fs->block_size, fs->block_count, le32(super + 24), le32(super + 28), root->uid, root->gid, root->mtime);
    fprintf(out, "mkfs.f2fs options:      -f -O %s -U %s -R %u:%u -s %u -z %u -T %" PRId64 " -r <image>\n", features, uuid_text, root->uid, root->gid, le32(super + 24), le32(super + 28), root->mtime);
}

static int write_configs(Context *ctx, const char *config_dir, const char *name) {
    char *fs_config_name = join_path(name, "_fs_config"), *contexts_name = join_path(name, "_file_contexts"), *options_name = join_path(name, "_mkfs_options"), *hardlinks_name = join_path(name, "_hardlinks");
    char *fs_config_path = fs_config_name ? join_path(config_dir, fs_config_name) : NULL;
    char *contexts_path = contexts_name ? join_path(config_dir, contexts_name) : NULL;
    char *options_path = options_name ? join_path(config_dir, options_name) : NULL;
    char *hardlinks_path = hardlinks_name ? join_path(config_dir, hardlinks_name) : NULL;
    free(fs_config_name);
    free(contexts_name);
    free(options_name);
    free(hardlinks_name);
    FILE *fs_config = fs_config_path ? artb_open_text(fs_config_path) : NULL;
    FILE *contexts = contexts_path ? artb_open_text(contexts_path) : NULL;
    FILE *options = options_path ? artb_open_text(options_path) : NULL;
    FILE *hardlinks = hardlinks_path ? artb_open_text(hardlinks_path) : NULL;
    int result = fs_config && contexts && options && hardlinks ? 0 : -1;
    for (size_t index = 0; !result && index < ctx->entries.count; index++) {
        const Entry *entry = &ctx->entries.items[index];
        fprintf(fs_config, "%s %u %u %04o", entry->path, entry->uid, entry->gid, entry->mode & 07777);
        if (entry->capabilities) fprintf(fs_config, " capabilities=0x%" PRIX64, entry->capabilities);
        fputc('\n', fs_config);
        if (entry->label && *entry->label) {
            escape_path(contexts, entry->path);
            fprintf(contexts, " %s\n", entry->label);
        }
        if (entry->link_to != NO_LINK) {
            const char *target = ctx->entries.items[entry->link_to].path;
            if (fwrite(target, 1, strlen(target) + 1, hardlinks) != strlen(target) + 1 || fwrite(entry->path, 1, strlen(entry->path) + 1, hardlinks) != strlen(entry->path) + 1) result = -1;
        }
    }
    if (!result) write_options(ctx, options, &ctx->entries.items[0]);
    if (fs_config && fclose(fs_config)) result = -1;
    if (contexts && fclose(contexts)) result = -1;
    if (options && fclose(options)) result = -1;
    if (hardlinks && fclose(hardlinks)) result = -1;
    free(fs_config_path);
    free(contexts_path);
    free(options_path);
    free(hardlinks_path);
    return result;
}

static const Entry *sort_items;

// Largest files are dispatched first so the slowest ones start early.
static int compare_files(const void *left, const void *right) {
    uint64_t a = sort_items[*(const size_t *)left].size, b = sort_items[*(const size_t *)right].size;
    return a < b ? 1 : a > b ? -1 : 0;
}

static void usage(const char *program) { fprintf(stderr, "usage: %s -i IMAGE -o OUTDIR [-n NAME] [-T THREADS] [--artb-progress]\n", program); }

static char *base_name(const char *image) {
    const char *start = image;
    for (const char *cursor = image; *cursor; cursor++) if (*cursor == '/' || *cursor == '\\') start = cursor + 1;
    const char *dot = strrchr(start, '.');
    return copy_string(start, dot && dot != start ? (size_t)(dot - start) : strlen(start));
}

static int scan(Context *ctx, Reader *reader) {
    Fs *fs = &ctx->fs;
    if (load_super(reader, fs) || load_nat(reader, fs) || reader_buffers(reader)) return -1;
    ctx->first_by_ino = malloc((size_t)fs->max_nid * sizeof(size_t));
    ctx->visited = calloc((size_t)fs->max_nid / 8 + 1, 1);
    unsigned char *raw = malloc(fs->block_size);
    if (!ctx->first_by_ino || !ctx->visited || !raw) {
        free(raw);
        return reader_fail(reader, "out of memory");
    }
    for (size_t index = 0; index < fs->max_nid; index++) ctx->first_by_ino[index] = NO_LINK;
    Inode root;
    Entry entry;
    char *path = copy_string("/", 1);
    int result = !path ? reader_fail(reader, "out of memory") : 0;
    if (!result) result = read_node(reader, fs->root_ino, raw) || parse_inode(reader, fs->root_ino, raw, &root) || describe(ctx, reader, raw, &root, path, &entry) ? -1 : 0;
    if (!result && (root.mode & MODE_TYPE) != MODE_DIR) result = reader_fail(reader, "root inode is not a directory");
    if (!result && entry_push(&ctx->entries, &entry)) result = reader_fail(reader, "out of memory");
    if (!result) {
        ctx->visited[fs->root_ino >> 3] |= (unsigned char)(1u << (fs->root_ino & 7));
        result = walk_dir(ctx, reader, raw, &root, "/", 0);
    }
    free(raw);
    return result;
}

static int run(int argc, char **argv) {
    const char *image = NULL, *outdir = NULL;
    char *name = NULL;
    unsigned threads = 0;
    int progress = 0;
    for (int index = 1; index < argc; index++) {
        if (!strcmp(argv[index], "-i") && index + 1 < argc) image = argv[++index];
        else if (!strcmp(argv[index], "-o") && index + 1 < argc) outdir = argv[++index];
        else if (!strcmp(argv[index], "-n") && index + 1 < argc) name = copy_string(argv[index + 1], strlen(argv[index + 1])), index++;
        else if (!strncmp(argv[index], "-T", 2)) threads = (unsigned)strtoul(argv[index][2] ? argv[index] + 2 : (index + 1 < argc ? argv[++index] : "0"), NULL, 10);
        else if (!strcmp(argv[index], "--artb-progress")) progress = 1;
        else {
            usage(argv[0]);
            return 2;
        }
    }
    if (!image || !outdir) {
        usage(argv[0]);
        return 2;
    }
    if (!name) name = base_name(image);
    crc_init();
    Context ctx;
    memset(&ctx, 0, sizeof(ctx));
    pthread_mutex_init(&ctx.error_lock, NULL);
    ctx.image = image;
    ctx.threads = threads ? threads : artb_logical_cpus();
    Reader reader;
    // The reader borrows ctx.fs, which scan fills in before any block beyond the superblock is read.
    if (reader_open(&reader, &ctx.fs, image) || scan(&ctx, &reader)) {
        reader_close(&reader);
        fprintf(stderr, "scan %s: %s\n", image, reader.error);
        return 1;
    }
    reader_close(&reader);
    char *root_dir = name ? join_path(outdir, "/") : NULL;
    char *out_root = root_dir ? join_path(root_dir, name) : NULL;
    char *config_dir = root_dir ? join_path(root_dir, "config/") : NULL;
    ctx.out_root = out_root;
    ctx.files = malloc((ctx.entries.count + 1) * sizeof(size_t));
    if (!out_root || !config_dir || !ctx.files) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
#ifdef _WIN32
    const char **paths = malloc((ctx.entries.count + 1) * sizeof(char *));
    if (!paths) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    for (size_t index = 0; index < ctx.entries.count; index++) paths[index] = ctx.entries.items[index].path;
    char *collision = artb_find_case_collision(paths, ctx.entries.count);
    free(paths);
    if (collision) {
        fprintf(stderr, "image contains paths differing only in case (%s); extract on a case-sensitive filesystem\n", collision);
        return 1;
    }
#endif
    if (artb_make_dir(outdir) || artb_make_dir(out_root) || artb_make_dir(config_dir)) {
        fprintf(stderr, "create output directories under %s failed\n", outdir);
        return 1;
    }
    for (size_t index = 0; index < ctx.entries.count; index++) {
        Entry *entry = &ctx.entries.items[index];
        if ((entry->mode & MODE_TYPE) == MODE_REG && entry->link_to == NO_LINK) {
            ctx.files[ctx.file_count++] = index;
            ctx.total_bytes += entry->size;
        }
    }
    sort_items = ctx.entries.items;
    qsort(ctx.files, ctx.file_count, sizeof(size_t), compare_files);
    Reporter reporter = {&ctx, 0};
    pthread_t reporter_thread;
    if (progress) {
        report_progress(&ctx);
        pthread_create(&reporter_thread, NULL, progress_worker, &reporter);
    }
    for (size_t index = 0; index < ctx.entries.count && !atomic_load(&ctx.failed); index++) {
        Entry *entry = &ctx.entries.items[index];
        char *path = out_path(&ctx, entry);
        if (!path) {
            fail(&ctx, "out of memory");
            break;
        }
        int status = 0;
        uint16_t type = entry->mode & MODE_TYPE;
        if (type == MODE_DIR) status = artb_make_dir(path);
        else if (type == MODE_LNK) status = artb_make_symlink(entry->symlink, path);
        else if (type != MODE_REG) {
            ArtbFile file = artb_out_create(path);
            status = file == ARTB_FILE_INVALID ? -1 : artb_file_close(file);
        }
        if (status) fail(&ctx, "create %s failed", entry->path);
        if (type != MODE_REG) atomic_fetch_add(&ctx.done_items, 1);
        free(path);
    }
    unsigned worker_count = ctx.threads;
    if (worker_count > ctx.file_count) worker_count = ctx.file_count ? (unsigned)ctx.file_count : 1;
    pthread_t *workers = calloc(worker_count, sizeof(pthread_t));
    if (!workers) fail(&ctx, "out of memory");
    unsigned started = 0;
    for (; workers && started < worker_count && !atomic_load(&ctx.failed); started++) {
        if (pthread_create(&workers[started], NULL, file_worker, &ctx)) {
            fail(&ctx, "start worker thread failed");
            break;
        }
    }
    for (unsigned index = 0; index < started; index++) pthread_join(workers[index], NULL);
    free(workers);
    for (size_t index = 0; index < ctx.entries.count && !atomic_load(&ctx.failed); index++) {
        Entry *entry = &ctx.entries.items[index];
        if (entry->link_to == NO_LINK) continue;
        char *target = out_path(&ctx, &ctx.entries.items[entry->link_to]), *path = out_path(&ctx, entry);
        if (!target || !path || artb_make_hardlink(target, path)) fail(&ctx, "link %s failed", entry->path);
        free(target);
        free(path);
        atomic_fetch_add(&ctx.done_items, 1);
    }
    for (size_t index = ctx.entries.count; index-- > 0 && !atomic_load(&ctx.failed);) {
        Entry *entry = &ctx.entries.items[index];
        if ((entry->mode & MODE_TYPE) != MODE_DIR && (entry->mode & MODE_TYPE) != MODE_LNK) continue;
        char *path = out_path(&ctx, entry);
        if (path) artb_set_times(path, entry->mtime, entry->mtime_nsec);
        free(path);
    }
    if (!atomic_load(&ctx.failed) && write_configs(&ctx, config_dir, name)) fail(&ctx, "write config files under %s failed", config_dir);
    if (progress) {
        atomic_store(&reporter.stop, 1);
        pthread_join(reporter_thread, NULL);
        report_progress(&ctx);
    }
    if (atomic_load(&ctx.failed)) {
        fprintf(stderr, "%s\n", ctx.error);
        return 1;
    }
    return 0;
}

#ifdef _WIN32
// wmain receives UTF-16 arguments, which are converted once so every path stays UTF-8 internally.
int wmain(int argc, wchar_t **wide) {
    char **argv = artb_utf8_argv(argc, wide);
    if (!argv) {
        fprintf(stderr, "read command line failed\n");
        return 1;
    }
    return run(argc, argv);
}
#else
int main(int argc, char **argv) { return run(argc, argv); }
#endif
