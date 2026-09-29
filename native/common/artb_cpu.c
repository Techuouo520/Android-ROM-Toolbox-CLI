#if defined(__linux__)
#define _GNU_SOURCE
#endif
#include "artb_cpu.h"

#if defined(_WIN32)
#include <windows.h>

// GetSystemInfo and std::thread::hardware_concurrency only see the current group of at most 64 processors.
unsigned artb_logical_cpus(void) {
    DWORD count = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    return count ? (unsigned)count : 1;
}
#else
#include <unistd.h>
#if defined(__linux__)
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Parses a kernel CPU list such as 0-3,6 into set; returns 0 when it is malformed.
static int artb_parse_cpu_list(const char *text, cpu_set_t *set) {
    CPU_ZERO(set);
    while (*text == ' ' || *text == '\t') text++;
    for (;;) {
        char *end;
        long first = strtol(text, &end, 10), last = first;
        if (end == text || first < 0) return 0;
        if (*end == '-') {
            text = end + 1;
            last = strtol(text, &end, 10);
            if (end == text) return 0;
        }
        if (last < first || last >= CPU_SETSIZE) return 0;
        for (long cpu = first; cpu <= last; cpu++) CPU_SET((int)cpu, set);
        if (*end != ',') return 1;
        text = end + 1;
    }
}

// Copies the rest of the first line of path that starts with prefix into line.
static int artb_read_field(const char *path, const char *prefix, char *line, size_t size) {
    FILE *file = fopen(path, "r");
    if (!file) return 0;
    size_t length = strlen(prefix);
    int found = 0;
    while (!found && fgets(line, (int)size, file)) found = strncmp(line, prefix, length) == 0;
    fclose(file);
    if (found) memmove(line, line + length, strlen(line + length) + 1);
    return found;
}

// Android's core_ctl pauses idle cores: they stay online and in the allowed mask but leave sched_getaffinity until load rises.
static unsigned artb_allowed_online_cpus(void) {
    char allowed_text[4096], online_text[4096];
    cpu_set_t allowed, online, both;
    if (!artb_read_field("/proc/self/status", "Cpus_allowed_list:", allowed_text, sizeof(allowed_text)) || !artb_read_field("/sys/devices/system/cpu/online", "", online_text, sizeof(online_text))) return 0;
    if (!artb_parse_cpu_list(allowed_text, &allowed) || !artb_parse_cpu_list(online_text, &online)) return 0;
    CPU_AND(&both, &allowed, &online);
    return (unsigned)CPU_COUNT(&both);
}
#endif

unsigned artb_logical_cpus(void) {
#if defined(__linux__)
    unsigned count_allowed = artb_allowed_online_cpus();
    if (count_allowed > 0) return count_allowed;
    cpu_set_t set;
    if (sched_getaffinity(0, sizeof(set), &set) == 0 && CPU_COUNT(&set) > 0) return (unsigned)CPU_COUNT(&set);
#endif
    long count = sysconf(_SC_NPROCESSORS_ONLN);
    return count > 0 ? (unsigned)count : 1;
}
#endif
