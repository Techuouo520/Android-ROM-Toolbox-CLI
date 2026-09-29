#pragma once
#define FNM_NOMATCH 1
#define FNM_NOESCAPE 0x01
#define FNM_PATHNAME 0x02
#define FNM_PERIOD 0x04
#ifdef __cplusplus
extern "C" {
#endif
int fnmatch(const char *pattern, const char *value, int flags);
#ifdef __cplusplus
}
#endif
