// Package fsinfo reads filesystem superblocks to recover the parameters needed to rebuild an image.
package fsinfo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"artb/internal/workspace"
)

const (
	superOffset          = 1024
	erofsMagic           = 0xE0F5E1E2
	erofsCompatXattrName = 0x4
	erofsIncompatZeroPad = 0x1
	erofsIncompatCompr   = 0x2
	erofsIncompatTail    = 0x10
	erofsIncompatFrags   = 0x20
)

// Order matches the Z_EROFS_COMPRESSION_* bits in available_compr_algs.
var erofsCompressors = []string{"lz4hc", "lzma", "deflate", "zstd"}

// EROFS describes an image in terms of mkfs.erofs options.
type EROFS struct {
	UUID      string
	Label     string
	Timestamp int64
	BlockSize uint32
	Params    workspace.EROFSParams
}

func readHead(path string, size int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer file.Close()
	head := make([]byte, size)
	count, err := io.ReadFull(file, head)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	return head[:count], nil
}

func formatUUID(raw []byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
}

func cString(raw []byte) string {
	if index := bytes.IndexByte(raw, 0); index >= 0 {
		raw = raw[:index]
	}
	return string(raw)
}

func ReadEROFS(path string) (EROFS, error) {
	var info EROFS
	head, err := readHead(path, 8192)
	if err != nil {
		return info, err
	}
	if len(head) < superOffset+128 {
		return info, fmt.Errorf("%q is too small for an EROFS superblock", path)
	}
	sb := head[superOffset:]
	le := binary.LittleEndian
	if le.Uint32(sb[0:]) != erofsMagic {
		return info, fmt.Errorf("%q is not an EROFS image", path)
	}
	compat, blockBits, extSlots, incompat := le.Uint32(sb[8:]), uint32(sb[12]), int(sb[13]), le.Uint32(sb[80:])
	info.BlockSize = 1 << blockBits
	info.Timestamp = int64(le.Uint64(sb[24:]))
	info.UUID = formatUUID(sb[48:64])
	info.Label = strings.TrimSpace(cString(sb[64:80]))
	params := &info.Params
	if incompat&erofsIncompatCompr != 0 {
		algorithms := le.Uint16(sb[84:])
		for bit, name := range erofsCompressors {
			if algorithms&(1<<bit) != 0 {
				params.Compression = name
				break
			}
		}
		// Compression configs follow the superblock as 4-byte aligned, length-prefixed records in bit order.
		offset := superOffset + 128 + 16*extSlots
		for bit := 0; bit < 16 && algorithms>>bit != 0; bit++ {
			if algorithms&(1<<bit) == 0 {
				continue
			}
			offset = (offset + 3) &^ 3
			if offset+2 > len(head) {
				break
			}
			length := int(le.Uint16(head[offset:]))
			offset += 2
			if bit == 0 && length >= 4 && offset+4 <= len(head) {
				if blocks := uint32(le.Uint16(head[offset+2:])); blocks > 1 {
					params.PclusterSize = blocks << blockBits
				}
			}
			offset += length
		}
	} else {
		// Pre-COMPR_CFGS images only knew LZ4; without zero padding they use the legacy layout.
		params.Compression = "lz4hc"
		if incompat&erofsIncompatZeroPad == 0 {
			params.Extended = append(params.Extended, "legacy-compress")
		}
	}
	if incompat&erofsIncompatTail != 0 {
		params.Extended = append(params.Extended, "ztailpacking")
	}
	if incompat&erofsIncompatFrags != 0 {
		// FRAGMENTS and DEDUPE share a bit; a packed inode only exists with fragments.
		if le.Uint64(sb[96:]) != 0 {
			params.Extended = append(params.Extended, "fragments")
		} else {
			params.Extended = append(params.Extended, "dedupe")
		}
	}
	if compat&erofsCompatXattrName != 0 {
		params.Extended = append(params.Extended, "xattr-name-filter")
	}
	return info, nil
}
