#include "config.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "e2p/e2p.h"
#include "ext2fs/ext2_fs.h"
#include "ext2fs/ext2fs.h"
#include "artb_cpu.h"
#include "artb_extract_io.h"

#define CHUNK_BLOCKS 256
#define NO_LINK SIZE_MAX

typedef struct {
    char *path;
    ext2_ino_t ino;
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
    const char *image;
    const char *out_root;
    unsigned threads;
    int progress;
    ext2_filsys fs;
    EntryList entries;
    size_t *first_by_ino;
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

static void decode_mtime(ext2_filsys fs, const struct ext2_inode_large *inode, int64_t *seconds, uint32_t *nanoseconds) {
    *seconds = (int32_t)inode->i_mtime;
    *nanoseconds = 0;
    if (EXT2_INODE_SIZE(fs->super) > EXT2_GOOD_OLD_INODE_SIZE && inode->i_extra_isize >= offsetof(struct ext2_inode_large, i_mtime_extra) + sizeof(inode->i_mtime_extra) - EXT2_GOOD_OLD_INODE_SIZE) {
        *seconds += (int64_t)(inode->i_mtime_extra & 3) << 32;
        *nanoseconds = inode->i_mtime_extra >> 2;
    }
}

// Android stores SELinux labels with a trailing NUL and file capabilities as vfs_cap_data.
static errcode_t read_security(ext2_filsys fs, ext2_ino_t ino, Entry *entry) {
    struct ext2_xattr_handle *handle = NULL;
    errcode_t error = ext2fs_xattrs_open(fs, ino, &handle);
    if (error) return error;
    error = ext2fs_xattrs_read(handle);
    if (!error) {
        void *value = NULL;
        size_t length = 0;
        if (!ext2fs_xattr_get(handle, "security.selinux", &value, &length)) {
            while (length && ((char *)value)[length - 1] == 0) length--;
            entry->label = copy_string(value, length);
            ext2fs_free_mem(&value);
            if (!entry->label) error = EXT2_ET_NO_MEMORY;
        }
        value = NULL;
        if (!error && !ext2fs_xattr_get(handle, "security.capability", &value, &length)) {
            const unsigned char *data = value;
            uint32_t magic = length >= 4 ? (uint32_t)data[0] | (uint32_t)data[1] << 8 | (uint32_t)data[2] << 16 | (uint32_t)data[3] << 24 : 0;
            uint32_t revision = magic & 0xFF000000u;
            if (revision == 0x01000000u && length == 12) entry->capabilities = (uint32_t)data[4] | (uint32_t)data[5] << 8 | (uint32_t)data[6] << 16 | (uint32_t)data[7] << 24;
            if ((revision == 0x02000000u || revision == 0x03000000u) && (length == 20 || length == 24)) entry->capabilities = ((uint64_t)((uint32_t)data[4] | (uint32_t)data[5] << 8 | (uint32_t)data[6] << 16 | (uint32_t)data[7] << 24)) | ((uint64_t)((uint32_t)data[12] | (uint32_t)data[13] << 8 | (uint32_t)data[14] << 16 | (uint32_t)data[15] << 24) << 32);
            ext2fs_free_mem(&value);
        }
    }
    ext2fs_xattrs_close(&handle);
    return error;
}

static errcode_t read_symlink(ext2_filsys fs, ext2_ino_t ino, struct ext2_inode_large *inode, char **target) {
    uint64_t size = EXT2_I_SIZE(inode);
    char *buffer = malloc(size + 1);
    if (!buffer) return EXT2_ET_NO_MEMORY;
    errcode_t error = 0;
    if (ext2fs_is_fast_symlink((struct ext2_inode *)inode)) {
        memcpy(buffer, inode->i_block, size);
    } else if (inode->i_flags & EXT4_INLINE_DATA_FL) {
        size_t length = 0;
        error = ext2fs_inline_data_get(fs, ino, (struct ext2_inode *)inode, buffer, &length);
    } else {
        ext2_file_t file;
        error = ext2fs_file_open(fs, ino, 0, &file);
        if (!error) {
            unsigned got = 0;
            error = ext2fs_file_read(file, buffer, (unsigned)size, &got);
            errcode_t closed = ext2fs_file_close(file);
            if (!error) error = closed;
            if (!error && got != size) error = EXT2_ET_SHORT_READ;
        }
    }
    buffer[size] = 0;
    if (error) {
        free(buffer);
        return error;
    }
    *target = buffer;
    return 0;
}

typedef struct {
    Context *ctx;
    const char *parent;
    errcode_t error;
} WalkState;

static errcode_t walk_dir(Context *ctx, ext2_ino_t dir, const char *parent);

static int walk_entry(ext2_ino_t dir, int entry_kind, struct ext2_dir_entry *dirent, int offset, int blocksize, char *buf, void *private) {
    (void)dir;
    (void)entry_kind;
    (void)offset;
    (void)blocksize;
    (void)buf;
    WalkState *state = private;
    Context *ctx = state->ctx;
    int length = ext2fs_dirent_name_len(dirent);
    if ((length == 1 && dirent->name[0] == '.') || (length == 2 && dirent->name[0] == '.' && dirent->name[1] == '.')) return 0;
    char *name = copy_string(dirent->name, (size_t)length);
    char *slash = name ? join_path(strcmp(state->parent, "/") ? state->parent : "", "/") : NULL;
    char *path = slash ? join_path(slash, name) : NULL;
    free(name);
    free(slash);
    if (!path) {
        state->error = EXT2_ET_NO_MEMORY;
        return DIRENT_ABORT;
    }
    struct ext2_inode_large inode;
    memset(&inode, 0, sizeof(inode));
    errcode_t error = ext2fs_read_inode_full(ctx->fs, dirent->inode, (struct ext2_inode *)&inode, sizeof(inode));
    Entry entry = {path, dirent->inode, inode.i_mode, inode_uid(inode), inode_gid(inode), EXT2_I_SIZE(&inode), 0, 0, 0, NULL, NULL, NO_LINK};
    decode_mtime(ctx->fs, &inode, &entry.mtime, &entry.mtime_nsec);
    if (!error) error = read_security(ctx->fs, dirent->inode, &entry);
    if (!error && LINUX_S_ISLNK(inode.i_mode)) error = read_symlink(ctx->fs, dirent->inode, &inode, &entry.symlink);
    if (!error && LINUX_S_ISREG(inode.i_mode)) {
        if (ctx->first_by_ino[dirent->inode] != NO_LINK) entry.link_to = ctx->first_by_ino[dirent->inode];
        else ctx->first_by_ino[dirent->inode] = ctx->entries.count;
    }
    if (!error && entry_push(&ctx->entries, &entry)) error = EXT2_ET_NO_MEMORY;
    if (!error && LINUX_S_ISDIR(inode.i_mode)) error = walk_dir(ctx, dirent->inode, path);
    if (error) {
        state->error = error;
        return DIRENT_ABORT;
    }
    return 0;
}

static errcode_t walk_dir(Context *ctx, ext2_ino_t dir, const char *parent) {
    WalkState state = {ctx, parent, 0};
    errcode_t error = ext2fs_dir_iterate2(ctx->fs, dir, 0, NULL, walk_entry, &state);
    return error ? error : state.error;
}

static char *out_path(Context *ctx, const Entry *entry) { return join_path(ctx->out_root, strcmp(entry->path, "/") ? entry->path : ""); }

// Extent runs are read in 1 MiB requests instead of block by block through ext2fs_file_read.
static errcode_t copy_extents(Context *ctx, ext2_filsys fs, const Entry *entry, struct ext2_inode_large *inode, ArtbFile file, unsigned char *buffer) {
    ext2_extent_handle_t handle;
    errcode_t error = ext2fs_extent_open2(fs, entry->ino, (struct ext2_inode *)inode, &handle);
    if (error) return error;
    uint64_t block_size = fs->blocksize, written = 0;
    struct ext2fs_extent extent;
    error = ext2fs_extent_get(handle, EXT2_EXTENT_ROOT, &extent);
    while (!error) {
        if ((extent.e_flags & EXT2_EXTENT_FLAGS_LEAF) && extent.e_len && extent.e_lblk * block_size < entry->size) {
            uint64_t start = extent.e_lblk * block_size;
            uint64_t length = (uint64_t)extent.e_len * block_size;
            if (length > entry->size - start) length = entry->size - start;
            if (start < written) {
                error = EXT2_ET_EXTENT_HEADER_BAD;
                break;
            }
            if (artb_out_zeros(file, start - written)) {
                error = errno ? (errcode_t)errno : EIO;
                break;
            }
            atomic_fetch_add(&ctx->done_bytes, start - written);
            if (extent.e_flags & EXT2_EXTENT_FLAGS_UNINIT) {
                if (artb_out_zeros(file, length)) error = errno ? (errcode_t)errno : EIO;
                atomic_fetch_add(&ctx->done_bytes, length);
            } else {
                blk64_t physical = extent.e_pblk;
                uint64_t remaining = length;
                while (remaining && !error) {
                    uint64_t blocks = (remaining + block_size - 1) / block_size;
                    if (blocks > CHUNK_BLOCKS) blocks = CHUNK_BLOCKS;
                    error = io_channel_read_blk64(fs->io, physical, (int)blocks, buffer);
                    if (error) break;
                    uint64_t bytes = blocks * block_size;
                    if (bytes > remaining) bytes = remaining;
                    if (artb_out_write(file, buffer, (size_t)bytes)) {
                        error = errno ? (errcode_t)errno : EIO;
                        break;
                    }
                    physical += blocks;
                    remaining -= bytes;
                    atomic_fetch_add(&ctx->done_bytes, bytes);
                }
            }
            written = start + length;
        }
        if (!error) error = ext2fs_extent_get(handle, EXT2_EXTENT_NEXT_LEAF, &extent);
    }
    ext2fs_extent_free(handle);
    if (error != EXT2_ET_EXTENT_NO_NEXT) return error;
    if (written < entry->size) {
        if (artb_out_zeros(file, entry->size - written)) return errno ? (errcode_t)errno : EIO;
        atomic_fetch_add(&ctx->done_bytes, entry->size - written);
    }
    return 0;
}

static errcode_t copy_generic(Context *ctx, ext2_filsys fs, const Entry *entry, ArtbFile file, unsigned char *buffer) {
    ext2_file_t source;
    errcode_t error = ext2fs_file_open(fs, entry->ino, 0, &source);
    if (error) return error;
    uint64_t total = 0;
    for (;;) {
        unsigned got = 0;
        error = ext2fs_file_read(source, buffer, CHUNK_BLOCKS * fs->blocksize, &got);
        if (error || got == 0) break;
        if (artb_out_write(file, buffer, got)) {
            error = errno ? (errcode_t)errno : EIO;
            break;
        }
        total += got;
        atomic_fetch_add(&ctx->done_bytes, got);
    }
    errcode_t closed = ext2fs_file_close(source);
    if (!error) error = closed;
    if (!error && total != entry->size) error = EXT2_ET_SHORT_READ;
    return error;
}

static errcode_t copy_inline(Context *ctx, ext2_filsys fs, const Entry *entry, struct ext2_inode_large *inode, ArtbFile file, unsigned char *buffer) {
    size_t length = 0;
    errcode_t error = ext2fs_inline_data_get(fs, entry->ino, (struct ext2_inode *)inode, buffer, &length);
    if (error) return error;
    if (length > entry->size) length = (size_t)entry->size;
    if (artb_out_write(file, buffer, length) || artb_out_zeros(file, entry->size - length)) return errno ? (errcode_t)errno : EIO;
    atomic_fetch_add(&ctx->done_bytes, entry->size);
    return 0;
}

static errcode_t extract_file(Context *ctx, ext2_filsys fs, const Entry *entry, unsigned char *buffer) {
    struct ext2_inode_large inode;
    memset(&inode, 0, sizeof(inode));
    errcode_t error = ext2fs_read_inode_full(fs, entry->ino, (struct ext2_inode *)&inode, sizeof(inode));
    if (error) return error;
    char *path = out_path(ctx, entry);
    if (!path) return EXT2_ET_NO_MEMORY;
    ArtbFile file = artb_out_create(path);
    if (file == ARTB_FILE_INVALID) {
        free(path);
        return errno ? (errcode_t)errno : EIO;
    }
    if (inode.i_flags & EXT4_INLINE_DATA_FL) error = copy_inline(ctx, fs, entry, &inode, file, buffer);
    else if (inode.i_flags & EXT4_EXTENTS_FL) error = copy_extents(ctx, fs, entry, &inode, file, buffer);
    else error = copy_generic(ctx, fs, entry, file, buffer);
    if (artb_file_close(file) && !error) error = EIO;
    if (!error && artb_set_times(path, entry->mtime, entry->mtime_nsec)) error = EIO;
    free(path);
    return error;
}

static void *file_worker(void *argument) {
    Context *ctx = argument;
    ext2_filsys fs = NULL;
    errcode_t error = ext2fs_open2(ctx->image, NULL, EXT2_FLAG_64BITS, 0, 0, default_io_manager, &fs);
    if (error) {
        fail(ctx, "open %s: %s", ctx->image, error_message(error));
        return NULL;
    }
    unsigned char *buffer = malloc((size_t)CHUNK_BLOCKS * fs->blocksize);
    if (!buffer) fail(ctx, "allocate read buffer");
    while (buffer && !atomic_load(&ctx->failed)) {
        size_t index = atomic_fetch_add(&ctx->next_file, 1);
        if (index >= ctx->file_count) break;
        const Entry *entry = &ctx->entries.items[ctx->files[index]];
        error = extract_file(ctx, fs, entry, buffer);
        if (error) {
            fail(ctx, "extract %s: %s", entry->path, error_message(error));
            break;
        }
        atomic_fetch_add(&ctx->done_items, 1);
    }
    free(buffer);
    ext2fs_close_free(&fs);
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

static int write_configs(Context *ctx, const char *config_dir, const char *name) {
    char *fs_config_name = join_path(name, "_fs_config"), *contexts_name = join_path(name, "_file_contexts"), *options_name = join_path(name, "_mkfs_options");
    char *fs_config_path = fs_config_name ? join_path(config_dir, fs_config_name) : NULL;
    char *contexts_path = contexts_name ? join_path(config_dir, contexts_name) : NULL;
    char *options_path = options_name ? join_path(config_dir, options_name) : NULL;
    free(fs_config_name);
    free(contexts_name);
    free(options_name);
    FILE *fs_config = fs_config_path ? artb_open_text(fs_config_path) : NULL;
    FILE *contexts = contexts_path ? artb_open_text(contexts_path) : NULL;
    FILE *options = options_path ? artb_open_text(options_path) : NULL;
    int result = fs_config && contexts && options ? 0 : -1;
    for (size_t index = 0; !result && index < ctx->entries.count; index++) {
        const Entry *entry = &ctx->entries.items[index];
        fprintf(fs_config, "%s %u %u %04o", entry->path, entry->uid, entry->gid, entry->mode & 07777);
        if (entry->capabilities) fprintf(fs_config, " capabilities=0x%" PRIX64, entry->capabilities);
        fputc('\n', fs_config);
        if (entry->label && *entry->label) {
            escape_path(contexts, entry->path);
            fprintf(contexts, " %s\n", entry->label);
        }
    }
    if (!result) {
        struct ext2_super_block *super = ctx->fs->super;
        const char *uuid = e2p_uuid2str(super->s_uuid);
        char label[EXT2_LABEL_LEN + 1] = "", mounted[sizeof(super->s_last_mounted) + 1] = "";
        memcpy(label, super->s_volume_name, EXT2_LABEL_LEN);
        memcpy(mounted, super->s_last_mounted, sizeof(super->s_last_mounted));
        char features[1024] = "";
        const __u32 masks[3] = {super->s_feature_compat, super->s_feature_incompat, super->s_feature_ro_compat};
        for (int kind = 0; kind < 3; kind++) {
            for (int bit = 0; bit < 32; bit++) {
                if (!(masks[kind] & (1u << bit))) continue;
                if (*features) strncat(features, ",", sizeof(features) - strlen(features) - 1);
                strncat(features, e2p_feature2string(kind, 1u << bit), sizeof(features) - strlen(features) - 1);
            }
        }
        time_t created = super->s_mkfs_time;
        char created_text[64] = "";
        struct tm *created_tm = gmtime(&created);
        if (created_tm) strftime(created_text, sizeof(created_text), "%Y-%m-%d %H:%M:%S UTC", created_tm);
        fprintf(options, "Filesystem volume name: %s\nLast mounted on:        %s\nFilesystem UUID:        %s\nFilesystem features:    %s\nBlock size:             %u\nBlock count:            %llu\nInode count:            %u\nInode size:             %u\nReserved block count:   %llu\nFilesystem created:     %s\n", *label ? label : "<none>", *mounted ? mounted : "<not available>", uuid, features, ctx->fs->blocksize, (unsigned long long)ext2fs_blocks_count(super), super->s_inodes_count, (unsigned)EXT2_INODE_SIZE(super), (unsigned long long)ext2fs_r_blocks_count(super), created_text);
        fprintf(options, "mke2fs options:         -t ext4 -b %u -I %u -N %u -m 0 -L \"%s\" -M \"%s\" -U %s -O %s <image> %llu\n", ctx->fs->blocksize, (unsigned)EXT2_INODE_SIZE(super), super->s_inodes_count, label, mounted, uuid, features, (unsigned long long)ext2fs_blocks_count(super));
    }
    if (fs_config && fclose(fs_config)) result = -1;
    if (contexts && fclose(contexts)) result = -1;
    if (options && fclose(options)) result = -1;
    free(fs_config_path);
    free(contexts_path);
    free(options_path);
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
    add_error_table(&et_ext2_error_table);
    Context ctx;
    memset(&ctx, 0, sizeof(ctx));
    pthread_mutex_init(&ctx.error_lock, NULL);
    ctx.image = image;
    ctx.threads = threads ? threads : artb_logical_cpus();
    ctx.progress = progress;
    errcode_t error = ext2fs_open2(image, NULL, EXT2_FLAG_64BITS, 0, 0, default_io_manager, &ctx.fs);
    if (error) {
        fprintf(stderr, "open %s: %s\n", image, error_message(error));
        return 1;
    }
    char *root_dir = name ? join_path(outdir, "/") : NULL;
    char *out_root = root_dir ? join_path(root_dir, name) : NULL;
    char *config_dir = root_dir ? join_path(root_dir, "config/") : NULL;
    ctx.out_root = out_root;
    ctx.first_by_ino = malloc(((size_t)ctx.fs->super->s_inodes_count + 1) * sizeof(size_t));
    if (!out_root || !config_dir || !ctx.first_by_ino) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    for (size_t index = 0; index <= ctx.fs->super->s_inodes_count; index++) ctx.first_by_ino[index] = NO_LINK;
    struct ext2_inode_large root;
    memset(&root, 0, sizeof(root));
    error = ext2fs_read_inode_full(ctx.fs, EXT2_ROOT_INO, (struct ext2_inode *)&root, sizeof(root));
    Entry root_entry = {copy_string("/", 1), EXT2_ROOT_INO, root.i_mode, inode_uid(root), inode_gid(root), 0, 0, 0, 0, NULL, NULL, NO_LINK};
    decode_mtime(ctx.fs, &root, &root_entry.mtime, &root_entry.mtime_nsec);
    if (!error) error = read_security(ctx.fs, EXT2_ROOT_INO, &root_entry);
    if (!error && entry_push(&ctx.entries, &root_entry)) error = EXT2_ET_NO_MEMORY;
    if (!error) error = walk_dir(&ctx, EXT2_ROOT_INO, "/");
    if (error) {
        fprintf(stderr, "scan %s: %s\n", image, error_message(error));
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
    ctx.files = malloc((ctx.entries.count + 1) * sizeof(size_t));
    if (!ctx.files) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    for (size_t index = 0; index < ctx.entries.count; index++) {
        Entry *entry = &ctx.entries.items[index];
        if (LINUX_S_ISREG(entry->mode) && entry->link_to == NO_LINK) {
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
        if (LINUX_S_ISDIR(entry->mode)) status = artb_make_dir(path);
        else if (LINUX_S_ISLNK(entry->mode)) status = artb_make_symlink(entry->symlink, path);
        else if (!LINUX_S_ISREG(entry->mode)) {
            ArtbFile file = artb_out_create(path);
            status = file == ARTB_FILE_INVALID ? -1 : artb_file_close(file);
        }
        if (status) fail(&ctx, "create %s failed", entry->path);
        if (!LINUX_S_ISREG(entry->mode)) atomic_fetch_add(&ctx.done_items, 1);
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
        if (!LINUX_S_ISDIR(entry->mode) && !LINUX_S_ISLNK(entry->mode)) continue;
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
    ext2fs_close_free(&ctx.fs);
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
