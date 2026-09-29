#pragma once
// MinGW has no <regex.h>; the vendored PCRE2 POSIX layer supplies regcomp and regexec for --exclude-regex and compression hints.
#include "../../../../upstream/erofs-tools/src/lib/pcre/src/pcre2posix.h"
