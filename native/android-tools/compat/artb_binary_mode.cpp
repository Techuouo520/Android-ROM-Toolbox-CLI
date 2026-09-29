#ifdef _WIN32
#include <fcntl.h>
#include <stdlib.h>

// liblp and libsparse open images without O_BINARY; text mode would stop at a 0x1A byte or rewrite line endings.
__attribute__((constructor)) static void artb_binary_mode(void) { _set_fmode(_O_BINARY); }
#endif
