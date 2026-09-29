#include <sys/stat.h>
#include "erofs/internal.h"
#include "liberofs_compress.h"
#include "liberofs_fragments.h"
#include "liberofs_metabox.h"

#define S_SHIFT 12

const char *erofs_frags_packedname = "packed_file";

unsigned char erofs_mode_to_ftype(umode_t mode) {
    static const unsigned char types[S_IFMT >> S_SHIFT] = {
        [S_IFREG >> S_SHIFT] = EROFS_FT_REG_FILE,
        [S_IFDIR >> S_SHIFT] = EROFS_FT_DIR,
        [S_IFCHR >> S_SHIFT] = EROFS_FT_CHRDEV,
        [S_IFBLK >> S_SHIFT] = EROFS_FT_BLKDEV,
        [S_IFIFO >> S_SHIFT] = EROFS_FT_FIFO,
        [S_IFSOCK >> S_SHIFT] = EROFS_FT_SOCK,
        [S_IFLNK >> S_SHIFT] = EROFS_FT_SYMLINK,
    };
    return types[(mode & S_IFMT) >> S_SHIFT];
}

int erofs_packedfile_read(struct erofs_sb_info *sbi, void *buffer, erofs_off_t length, erofs_off_t position) {
    struct erofs_inode inode = {.sbi = sbi};
    struct erofs_vfile file;
    inode.nid = sbi->packed_nid;
    int error = erofs_read_inode_from_disk(&inode);
    if (!error) error = erofs_iopen(&file, &inode);
    if (!error) error = erofs_pread(&file, buffer, length, position);
    return error;
}

const struct erofs_algorithm *z_erofs_list_available_compressors(int *index) {
    (void)index;
    return NULL;
}

// super.c and xattr.c call these write-side helpers from functions extract never runs; lld resolves symbols before --gc-sections drops those callers, unlike GNU ld.
int z_erofs_compress_exit(struct erofs_sb_info *sbi) {
    (void)sbi;
    return 0;
}

int erofs_packedfile(struct erofs_sb_info *sbi) {
    (void)sbi;
    return -EOPNOTSUPP;
}

struct erofs_bufmgr *erofs_metadata_bmgr(struct erofs_sb_info *sbi, bool mbox) {
    (void)sbi;
    (void)mbox;
    return NULL;
}
