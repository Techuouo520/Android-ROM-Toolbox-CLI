#pragma once
#ifdef _WIN32
#include <filesystem>
#include <string>
#include <time.h>
static inline struct tm* artb_localtime_r(const time_t* timer, struct tm* result) { return localtime_s(result, timer) == 0 ? result : nullptr; }
#define localtime_r artb_localtime_r
#define __builtin_align_up(value, alignment) (((value) + (alignment) - 1) / (alignment) * (alignment))
namespace android::base { inline bool Realpath(const std::string& path, std::string* result) { std::error_code error; auto resolved = std::filesystem::canonical(path, error); if (error) return false; *result = resolved.string(); return true; } }
#endif
