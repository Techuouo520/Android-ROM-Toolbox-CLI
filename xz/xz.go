// Package xz decodes complete xz streams memory-to-memory with the 7-Zip LZMA SDK.
package xz

/*
#cgo CFLAGS: -O3 -DZ7_ST -I${SRCDIR}/../upstream/lzma-sdk/C
#include "artb_xz.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

var (
	ErrTruncated    = errors.New("xz: truncated stream")
	ErrTrailingData = errors.New("xz: trailing data after stream")
	ErrCorrupt      = errors.New("xz: corrupt data")
	ErrUnsupported  = errors.New("xz: unsupported stream")
	ErrOutputFull   = errors.New("xz: output buffer too small")
)

var (
	initOnce sync.Once
	decoders = make(chan *C.ArtbXzDecoder, max(2*runtime.GOMAXPROCS(0), 8))
)

// AsmEnabled reports whether the MASM/ELF LzmaDecOpt kernel is linked in.
func AsmEnabled() bool { return C.artb_xz_asm_enabled() != 0 }

// Decode unpacks one complete xz stream from src into dst and returns the decoded length.
func Decode(dst, src []byte) (int, error) {
	if len(src) == 0 {
		return 0, ErrTruncated
	}
	decoder, err := acquire()
	if err != nil {
		return 0, err
	}
	var dstPointer *C.uint8_t
	if len(dst) > 0 {
		dstPointer = (*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(dst)))
	}
	var written C.size_t
	code := C.artb_xz_decode(decoder, (*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(src))), C.size_t(len(src)), dstPointer, C.size_t(len(dst)), &written)
	release(decoder)
	if code != C.ARTB_XZ_OK {
		return int(written), decodeError(int(code), int(written), len(dst))
	}
	return int(written), nil
}

func acquire() (*C.ArtbXzDecoder, error) {
	initOnce.Do(func() { C.artb_xz_init() })
	select {
	case decoder := <-decoders:
		return decoder, nil
	default:
	}
	decoder := C.artb_xz_new()
	if decoder == nil {
		return nil, errors.New("xz: allocate decoder")
	}
	return decoder, nil
}

func release(decoder *C.ArtbXzDecoder) {
	select {
	case decoders <- decoder:
	default:
		C.artb_xz_free(decoder)
	}
}

func decodeError(code, written, capacity int) error {
	switch code {
	case C.ARTB_XZ_TRUNCATED:
		return ErrTruncated
	case C.ARTB_XZ_TRAILING:
		return ErrTrailingData
	case 1:
		if written == capacity {
			return ErrOutputFull
		}
		return fmt.Errorf("%w: data error", ErrCorrupt)
	case 2:
		return errors.New("xz: out of memory")
	case 3:
		return fmt.Errorf("%w: checksum mismatch", ErrCorrupt)
	case 4:
		return ErrUnsupported
	case 6:
		return ErrTruncated
	case 7:
		return ErrOutputFull
	case 17:
		return fmt.Errorf("%w: invalid stream header", ErrCorrupt)
	default:
		return fmt.Errorf("xz: decoder error %d", code)
	}
}
