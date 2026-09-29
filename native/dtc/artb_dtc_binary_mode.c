#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>

// dtc opens blobs and reads or writes stdin and stdout without O_BINARY; text mode would rewrite line endings in dtb data.
__attribute__((constructor)) static void artb_dtc_binary_mode(void) {
    _set_fmode(_O_BINARY);
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
}
#endif
