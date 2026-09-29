
#pragma once

#if HAVE_SYS_STAT_H
#include_next <sys/stat.h>
#endif

#ifndef lstat
#define lstat stat
#endif

#ifndef S_ISLNK
#ifdef __S_IFLNK
#define S_ISLNK(mode)	__S_ISTYPE((mode), __S_IFLNK)
#else
/* MinGW stat never reports links, but artb's lstat maps Cygwin placeholders to this type */
#ifndef S_IFLNK
#define S_IFLNK	0120000
#endif
#define S_ISLNK(mode)	(((mode) & S_IFMT) == S_IFLNK)
#endif
#endif

#define link(a, b)	CreateHardLink((a), (b), NULL)
