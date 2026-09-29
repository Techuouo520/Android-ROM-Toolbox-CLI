//go:build artb_lzmaasm && (linux || android || darwin)

// cgo assembles this with the C compiler, pulling in the LZMA SDK's GNU-syntax ARM64 LzmaDec_DecodeReal_3.
#include "../upstream/lzma-sdk/Asm/arm64/LzmaDecOpt.S"

// The SDK source has no stack note, and older GNU linkers would then mark the whole binary's stack executable.
#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
