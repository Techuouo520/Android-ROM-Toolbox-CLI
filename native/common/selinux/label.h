#pragma once

#include <selinux/selinux.h>

// Exact-path subset of the libselinux labeling API; artb resolves regular expressions before invoking the builders.
#define SELABEL_CTX_FILE 0
#define SELABEL_OPT_UNUSED 0
#define SELABEL_OPT_VALIDATE 1
#define SELABEL_OPT_BASEONLY 2
#define SELABEL_OPT_PATH 3
#define SELABEL_OPT_SUBSET 4
#define SELABEL_OPT_DIGEST 5

#ifdef __cplusplus
extern "C" {
#endif

struct selabel_handle;

struct selinux_opt {
    int type;
    const char *value;
};

struct selabel_handle *selabel_open(unsigned int backend, const struct selinux_opt *opts, unsigned nopts);
void selabel_close(struct selabel_handle *handle);
int selabel_lookup(struct selabel_handle *handle, char **con, const char *key, int type);

#ifdef __cplusplus
}
#endif
