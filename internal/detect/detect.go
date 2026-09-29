package detect

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

type Type string

const (
	Unknown    Type = "unknown"
	ZIP        Type = "zip"
	Payload    Type = "payload"
	Sparse     Type = "android-sparse"
	Super      Type = "android-super"
	Boot       Type = "android-boot"
	VendorBoot Type = "android-vendor-boot"
	EROFS      Type = "erofs"
	Ext4       Type = "ext4"
	F2FS       Type = "f2fs"
	DTB        Type = "dtb"
	DTBO       Type = "android-dtbo"
	VBMeta     Type = "android-vbmeta"
)

const (
	sparseMagic uint32 = 0xed26ff3a
	superMagic  uint32 = 0x616c4467
	erofsMagic  uint32 = 0xe0f5e1e2
	f2fsMagic   uint32 = 0xf2f52010
	ext4Magic   uint16 = 0xef53
	superOffset        = 4096
	erofsOffset        = 1024
	f2fsOffset         = 1024
	ext4Offset         = 1080
)

type Result struct {
	Type Type  `json:"type"`
	Size int64 `json:"size"`
}

func File(path string) (Result, error) {
	file, err := os.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("open %q: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Result{}, fmt.Errorf("stat %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return Result{}, fmt.Errorf("inspect %q: not a regular file", path)
	}
	return ReaderAt(file, info.Size()), nil
}

func ReaderAt(reader io.ReaderAt, size int64) Result {
	result := Result{Type: Unknown, Size: size}
	if matchAt(reader, size, 0, []byte("CrAU")) {
		result.Type = Payload
		return result
	}
	if matchZIP(reader, size) {
		result.Type = ZIP
		return result
	}
	if uint32At(reader, size, 0) == sparseMagic {
		result.Type = Sparse
		return result
	}
	if matchAt(reader, size, 0, []byte("ANDROID!")) {
		result.Type = Boot
		return result
	}
	if matchAt(reader, size, 0, []byte("VNDRBOOT")) {
		result.Type = VendorBoot
		return result
	}
	if matchAt(reader, size, 0, []byte("AVB0")) {
		result.Type = VBMeta
		return result
	}
	if matchAt(reader, size, 0, []byte{0xd7, 0xb7, 0xab, 0x1e}) {
		result.Type = DTBO
		return result
	}
	if matchAt(reader, size, 0, []byte{0xd0, 0x0d, 0xfe, 0xed}) {
		result.Type = DTB
		return result
	}
	if uint32At(reader, size, superOffset) == superMagic {
		result.Type = Super
		return result
	}
	if uint32At(reader, size, erofsOffset) == erofsMagic {
		result.Type = EROFS
		return result
	}
	if uint32At(reader, size, f2fsOffset) == f2fsMagic {
		result.Type = F2FS
		return result
	}
	if uint16At(reader, size, ext4Offset) == ext4Magic {
		result.Type = Ext4
	}
	return result
}

func matchZIP(reader io.ReaderAt, size int64) bool {
	if size < 4 {
		return false
	}
	var signature [4]byte
	if _, err := reader.ReadAt(signature[:], 0); err != nil {
		return false
	}
	return bytes.Equal(signature[:], []byte{'P', 'K', 3, 4}) || bytes.Equal(signature[:], []byte{'P', 'K', 5, 6}) || bytes.Equal(signature[:], []byte{'P', 'K', 7, 8})
}

func matchAt(reader io.ReaderAt, size, offset int64, magic []byte) bool {
	if offset < 0 || size < offset+int64(len(magic)) {
		return false
	}
	buffer := make([]byte, len(magic))
	if _, err := reader.ReadAt(buffer, offset); err != nil {
		return false
	}
	return bytes.Equal(buffer, magic)
}

func uint16At(reader io.ReaderAt, size, offset int64) uint16 {
	var buffer [2]byte
	if offset < 0 || size < offset+int64(len(buffer)) {
		return 0
	}
	if _, err := reader.ReadAt(buffer[:], offset); err != nil {
		return 0
	}
	return binary.LittleEndian.Uint16(buffer[:])
}

func uint32At(reader io.ReaderAt, size, offset int64) uint32 {
	var buffer [4]byte
	if offset < 0 || size < offset+int64(len(buffer)) {
		return 0
	}
	if _, err := reader.ReadAt(buffer[:], offset); err != nil {
		return 0
	}
	return binary.LittleEndian.Uint32(buffer[:])
}
