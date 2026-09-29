package fsinfo

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"artb/internal/workspace"
)

const ext4Magic = 0xEF53

type featureName struct {
	mask uint32
	name string
}

// Names follow e2p so mke2fs -O accepts them; state flags such as needs_recovery are left out on purpose.
var (
	ext4Compat   = []featureName{{0x1, "dir_prealloc"}, {0x2, "imagic_inodes"}, {0x4, "has_journal"}, {0x8, "ext_attr"}, {0x10, "resize_inode"}, {0x20, "dir_index"}, {0x100, "sparse_super2"}, {0x200, "fast_commit"}, {0x400, "stable_inodes"}, {0x800, "orphan_file"}}
	ext4ROCompat = []featureName{{0x1, "sparse_super"}, {0x2, "large_file"}, {0x8, "huge_file"}, {0x10, "uninit_bg"}, {0x20, "dir_nlink"}, {0x40, "extra_isize"}, {0x100, "quota"}, {0x200, "bigalloc"}, {0x400, "metadata_csum"}, {0x1000, "read-only"}, {0x2000, "project"}, {0x8000, "verity"}}
	ext4Incompat = []featureName{{0x2, "filetype"}, {0x10, "meta_bg"}, {0x40, "extent"}, {0x80, "64bit"}, {0x100, "mmp"}, {0x200, "flex_bg"}, {0x400, "ea_inode"}, {0x2000, "metadata_csum_seed"}, {0x4000, "large_dir"}, {0x8000, "inline_data"}, {0x10000, "encrypt"}, {0x20000, "casefold"}}
)

const (
	ext4ROCompatSharedBlocks = 0x4000
	ext4Incompat64Bit        = 0x80
	ext4IncompatFlexBG       = 0x200
)

// EXT4 describes an image in terms of mke2fs and e2fsdroid options.
type EXT4 struct {
	UUID      string
	Label     string
	Timestamp int64
	BlockSize uint32
	Params    workspace.EXT4Params
}

func ReadEXT4(path string) (EXT4, error) {
	var info EXT4
	head, err := readHead(path, 2048)
	if err != nil {
		return info, err
	}
	if len(head) < 2048 {
		return info, fmt.Errorf("%q is too small for an EXT4 superblock", path)
	}
	sb := head[superOffset:]
	le := binary.LittleEndian
	if le.Uint16(sb[56:]) != ext4Magic {
		return info, fmt.Errorf("%q is not an EXT4 image", path)
	}
	compat, incompat, roCompat := le.Uint32(sb[92:]), le.Uint32(sb[96:]), le.Uint32(sb[100:])
	info.BlockSize = 1024 << le.Uint32(sb[24:])
	info.UUID = formatUUID(sb[104:120])
	info.Label = cString(sb[120:136])
	params := &info.Params
	params.BlockCount = uint64(le.Uint32(sb[4:]))
	params.ReservedBlocks = uint64(le.Uint32(sb[8:]))
	if incompat&ext4Incompat64Bit != 0 {
		params.BlockCount |= uint64(le.Uint32(sb[336:])) << 32
		params.ReservedBlocks |= uint64(le.Uint32(sb[340:])) << 32
	}
	params.InodeCount = le.Uint32(sb[0:])
	params.InodeSize = le.Uint16(sb[88:])
	params.BlocksPerGroup = le.Uint32(sb[32:])
	params.LastMounted = cString(sb[136:200])
	params.HashSeed = formatUUID(sb[236:252])
	// s_flags records whether directory hashes were built with signed or unsigned chars; mke2fs would otherwise take the host's.
	switch flags := le.Uint32(sb[352:]); {
	case flags&0x2 != 0:
		params.HashSignedness = "unsigned"
	case flags&0x1 != 0:
		params.HashSignedness = "signed"
	}
	params.CreatedAt = int64(le.Uint32(sb[264:]))
	if incompat&ext4IncompatFlexBG != 0 {
		params.FlexBGSize = 1 << sb[372]
	}
	params.SharedBlocks = roCompat&ext4ROCompatSharedBlocks != 0
	for _, set := range []struct {
		value uint32
		names []featureName
	}{{compat, ext4Compat}, {roCompat, ext4ROCompat}, {incompat, ext4Incompat}} {
		for _, feature := range set.names {
			if set.value&feature.mask != 0 {
				params.Features = append(params.Features, feature.name)
			}
		}
	}
	info.Timestamp, err = rootInodeMtime(path, info.BlockSize, sb, incompat&ext4Incompat64Bit != 0)
	if err != nil {
		return info, err
	}
	return info, nil
}

// rootInodeMtime reads inode 2 so rebuilt files keep the fixed timestamp the image was built with.
func rootInodeMtime(path string, blockSize uint32, sb []byte, wide bool) (int64, error) {
	le := binary.LittleEndian
	file, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open %q: %w", path, err)
	}
	defer file.Close()
	descriptorBlock := uint64(le.Uint32(sb[20:])) + 1
	descriptor := make([]byte, 64)
	if _, err = file.ReadAt(descriptor, int64(descriptorBlock)*int64(blockSize)); err != nil {
		return 0, fmt.Errorf("read group descriptor of %q: %w", path, err)
	}
	table := uint64(le.Uint32(descriptor[8:]))
	if wide && le.Uint16(sb[254:]) >= 64 {
		table |= uint64(le.Uint32(descriptor[40:])) << 32
	}
	inode := make([]byte, 20)
	if _, err = file.ReadAt(inode, int64(table)*int64(blockSize)+int64(le.Uint16(sb[88:]))); err != nil {
		return 0, fmt.Errorf("read root inode of %q: %w", path, err)
	}
	return int64(le.Uint32(inode[16:])), nil
}

// MkfsFeatures lists features for mke2fs -O; shared_blocks is produced by e2fsdroid -s instead.
func MkfsFeatures(params workspace.EXT4Params) string {
	return "none," + strings.Join(params.Features, ",")
}
