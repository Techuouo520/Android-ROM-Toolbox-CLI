#include <selinux/label.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct artb_label {
    char *path;
    char *context;
    size_t order;
};

struct selabel_handle {
    struct artb_label *labels;
    size_t count;
};

// file_contexts keys are regular expressions; the resolved files artb writes only escape literal characters.
static char *unescape(const char *text) {
    char *value = malloc(strlen(text) + 1), *out = value;
    if (!value) return NULL;
    for (; *text; text++) {
        if (*text == '\\' && text[1]) text++;
        *out++ = *text;
    }
    *out = 0;
    return value;
}

static int compare_labels(const void *left, const void *right) {
    const struct artb_label *a = left, *b = right;
    int result = strcmp(a->path, b->path);
    if (result) return result;
    return a->order < b->order ? -1 : a->order > b->order;
}

void freecon(char *con) { free(con); }

void selabel_close(struct selabel_handle *handle) {
    if (!handle) return;
    for (size_t index = 0; index < handle->count; index++) {
        free(handle->labels[index].path);
        free(handle->labels[index].context);
    }
    free(handle->labels);
    free(handle);
}

struct selabel_handle *selabel_open(unsigned int backend, const struct selinux_opt *opts, unsigned nopts) {
    const char *path = NULL;
    if (backend != SELABEL_CTX_FILE) { errno = EINVAL; return NULL; }
    for (unsigned index = 0; index < nopts; index++)
        if (opts[index].type == SELABEL_OPT_PATH) path = opts[index].value;
    if (!path) { errno = EINVAL; return NULL; }
    FILE *file = fopen(path, "rb");
    if (!file) return NULL;
    struct selabel_handle *handle = calloc(1, sizeof(*handle));
    size_t capacity = 0;
    char line[8192];
    if (!handle) { fclose(file); errno = ENOMEM; return NULL; }
    while (fgets(line, sizeof(line), file)) {
        char *fields[3] = {0};
        int count = 0;
        for (char *token = strtok(line, " \t\r\n"); token && count < 3; token = strtok(NULL, " \t\r\n")) fields[count++] = token;
        if (count < 2 || fields[0][0] == '#') continue;
        // An optional file type column sits between the path and the context.
        const char *context = fields[count - 1];
        if (handle->count == capacity) {
            capacity = capacity ? capacity * 2 : 1024;
            struct artb_label *grown = realloc(handle->labels, capacity * sizeof(*grown));
            if (!grown) { fclose(file); selabel_close(handle); errno = ENOMEM; return NULL; }
            handle->labels = grown;
        }
        struct artb_label *label = &handle->labels[handle->count];
        label->path = unescape(fields[0]);
        label->context = strdup(context);
        label->order = handle->count;
        if (!label->path || !label->context) { free(label->path); free(label->context); fclose(file); selabel_close(handle); errno = ENOMEM; return NULL; }
        handle->count++;
    }
    fclose(file);
    qsort(handle->labels, handle->count, sizeof(*handle->labels), compare_labels);
    return handle;
}

int selabel_lookup(struct selabel_handle *handle, char **con, const char *key, int type) {
    (void)type;
    // libselinux collapses repeated slashes, which sload.f2fs produces by joining the mount point "/" with "/path".
    char *clean = NULL;
    if (strstr(key, "//")) {
        if (!(clean = malloc(strlen(key) + 1))) { errno = ENOMEM; return -1; }
        char *out = clean;
        for (const char *in = key; *in; in++)
            if (*in != '/' || out == clean || out[-1] != '/') *out++ = *in;
        *out = 0;
        key = clean;
    }
    size_t low = 0, high = handle ? handle->count : 0, found = (size_t)-1;
    // Later duplicates win, so take the last entry of the matching run.
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        int result = strcmp(handle->labels[middle].path, key);
        if (result <= 0) {
            if (!result) found = middle;
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    free(clean);
    if (found == (size_t)-1) { errno = ENOENT; return -1; }
    if (!strcmp(handle->labels[found].context, "<<none>>")) { errno = ENOENT; return -1; }
    *con = strdup(handle->labels[found].context);
    if (!*con) { errno = ENOMEM; return -1; }
    return 0;
}
