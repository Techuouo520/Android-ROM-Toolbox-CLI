#include <stddef.h>
#include <stdlib.h>

// Bionic only gained qsort_r in API 36, while gozstd's prebuilt glibc libzstd references it from the dictionary builder.
static __thread int (*artb_compare)(const void *, const void *, void *);
static __thread void *artb_context;

static int artb_trampoline(const void *left, const void *right) { return artb_compare(left, right, artb_context); }

void qsort_r(void *base, size_t count, size_t size, int (*compare)(const void *, const void *, void *), void *context) {
    int (*saved_compare)(const void *, const void *, void *) = artb_compare;
    void *saved_context = artb_context;
    artb_compare = compare, artb_context = context;
    qsort(base, count, size, artb_trampoline);
    artb_compare = saved_compare, artb_context = saved_context;
}
