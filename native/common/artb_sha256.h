#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// FIPS 180-4 SHA-256 of one buffer; replaces OpenSSL for the checksums liblp needs.
void artb_sha256(const void *data, size_t length, uint8_t out[32]);

#ifdef __cplusplus
}
#endif
