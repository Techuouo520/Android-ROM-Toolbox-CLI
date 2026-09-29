package fsinfo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"unicode/utf16"

	"artb/internal/workspace"
)

const (
	f2fsMagic           = 0xF2F52010
	f2fsSuperSize       = 3072
	f2fsSuperCRC        = 3068
	f2fsFeatureSBCRC    = 0x800
	f2fsFeatureCasefold = 0x1000
	f2fsCPBitmap        = 192
	f2fsCPUmount        = 0x1
	f2fsCPCompact       = 0x4
	f2fsCPFastboot      = 0x20
	f2fsCPLargeNAT      = 0x400
)

// Names follow the mkfs.f2fs -O table; blkzoned is left out because mkfs cannot set it on an image file.
var f2fsFeatures = []featureName{{0x1, "encrypt"}, {0x8, "extra_attr"}, {0x10, "project_quota"}, {0x20, "inode_checksum"}, {0x40, "flexible_inline_xattr"}, {0x80, "quota"}, {0x100, "inode_crtime"}, {0x200, "lost_found"}, {0x400, "verity"}, {0x800, "sb_checksum"}, {0x1000, "casefold"}, {0x2000, "compression"}, {0x4000, "ro"}}

// F2FS describes an image in terms of mkfs.f2fs and sload.f2fs options.
type F2FS struct {
	UUID      string
	Label     string
	Timestamp int64
	BlockSize uint32
	Params    workspace.F2FSParams
}

// f2fsCRC is the reflected CRC32 f2fs uses: caller-chosen seed and no final inversion.
func f2fsCRC(seed uint32, data []byte) uint32 {
	return ^crc32.Update(^seed, crc32.IEEETable, data)
}

func ReadF2FS(path string) (F2FS, error) {
	var info F2FS
	file, err := os.Open(path)
	if err != nil {
		return info, fmt.Errorf("open %q: %w", path, err)
	}
	defer file.Close()
	sb, err := f2fsSuper(file)
	if err != nil {
		return info, fmt.Errorf("%q: %w", path, err)
	}
	le := binary.LittleEndian
	feature := le.Uint32(sb[2180:])
	info.BlockSize = 1 << le.Uint32(sb[16:])
	info.UUID = formatUUID(sb[108:124])
	units := make([]uint16, 0, 512)
	for index := 0; index < 512; index++ {
		unit := le.Uint16(sb[124+2*index:])
		if unit == 0 {
			break
		}
		units = append(units, unit)
	}
	info.Label = string(utf16.Decode(units))
	params := &info.Params
	params.BlockCount = le.Uint64(sb[36:])
	params.SegmentsPerSection = le.Uint32(sb[24:])
	params.SectionsPerZone = le.Uint32(sb[28:])
	params.Version = cString(sb[1668 : 1668+252])
	for _, name := range f2fsFeatures {
		if feature&name.mask != 0 {
			params.Features = append(params.Features, name.name)
		}
	}
	// Encoding 1 is utf8; flag 1 is strict mode.
	if feature&f2fsFeatureCasefold != 0 && le.Uint16(sb[2758:]) == 1 {
		params.Encoding = "utf8"
		if le.Uint16(sb[2760:])&1 != 0 {
			params.Encoding = "utf8:strict"
		}
	}
	if info.Timestamp, err = f2fsRootMtime(file, sb); err != nil {
		return info, fmt.Errorf("%q: %w", path, err)
	}
	return info, nil
}

// f2fsSuper returns the primary superblock, or the backup in block 1 when the primary fails its checksum.
func f2fsSuper(file io.ReaderAt) ([]byte, error) {
	le := binary.LittleEndian
	for _, offset := range []int64{superOffset, 4096 + superOffset, 16384 + superOffset} {
		sb := make([]byte, f2fsSuperSize)
		if _, err := file.ReadAt(sb, offset); err != nil || le.Uint32(sb) != f2fsMagic {
			continue
		}
		logBlock := le.Uint32(sb[16:])
		if logBlock < 12 || logBlock > 14 || (offset != superOffset && offset != int64(1)<<logBlock+superOffset) {
			continue
		}
		if le.Uint32(sb[2180:])&f2fsFeatureSBCRC != 0 && (le.Uint32(sb[32:]) != f2fsSuperCRC || f2fsCRC(f2fsMagic, sb[:f2fsSuperCRC]) != le.Uint32(sb[f2fsSuperCRC:])) {
			continue
		}
		return sb, nil
	}
	return nil, errors.New("no valid F2FS superblock")
}

type f2fsLayout struct {
	file         io.ReaderAt
	blockSize    uint64
	logSegBlocks uint32
}

func (layout f2fsLayout) block(address uint64) ([]byte, error) {
	block := make([]byte, layout.blockSize)
	if _, err := layout.file.ReadAt(block, int64(address*layout.blockSize)); err != nil {
		return nil, fmt.Errorf("read block %d: %w", address, err)
	}
	return block, nil
}

func (layout f2fsLayout) checkpointBlock(address uint64) ([]byte, bool) {
	block, err := layout.block(address)
	if err != nil {
		return nil, false
	}
	le := binary.LittleEndian
	offset := uint64(le.Uint32(block[164:]))
	if offset < f2fsCPBitmap || offset > layout.blockSize-4 {
		return nil, false
	}
	crc := f2fsCRC(f2fsMagic, block[:offset])
	if offset < layout.blockSize-4 {
		crc = f2fsCRC(crc, block[offset+4:])
	}
	return block, crc == le.Uint32(block[offset:])
}

// pack validates a checkpoint pack by its checksums and matching first and last versions.
func (layout f2fsLayout) pack(start uint64) (uint64, bool) {
	first, ok := layout.checkpointBlock(start)
	if !ok {
		return 0, false
	}
	total := uint64(binary.LittleEndian.Uint32(first[136:]))
	if total < 2 || total > 1<<layout.logSegBlocks {
		return 0, false
	}
	last, ok := layout.checkpointBlock(start + total - 1)
	if !ok || binary.LittleEndian.Uint64(first) != binary.LittleEndian.Uint64(last) {
		return 0, false
	}
	return binary.LittleEndian.Uint64(first), true
}

// f2fsRootMtime finds the root inode through the newest checkpoint's NAT journal or NAT block, so rebuilt files keep the image timestamp.
func f2fsRootMtime(file io.ReaderAt, sb []byte) (int64, error) {
	le := binary.LittleEndian
	layout := f2fsLayout{file: file, blockSize: 1 << le.Uint32(sb[16:]), logSegBlocks: le.Uint32(sb[20:])}
	if layout.logSegBlocks < 4 || layout.logSegBlocks > 12 {
		return 0, errors.New("unsupported F2FS segment size")
	}
	segBlocks := uint64(1) << layout.logSegBlocks
	cpAddress, natAddress, payload, root := uint64(le.Uint32(sb[76:])), uint64(le.Uint32(sb[84:])), uint64(le.Uint32(sb[1664:])), le.Uint32(sb[96:])
	if payload > segBlocks {
		return 0, errors.New("F2FS checkpoint payload exceeds segment size")
	}
	versionOne, okOne := layout.pack(cpAddress)
	versionTwo, okTwo := layout.pack(cpAddress + segBlocks)
	if !okOne && !okTwo {
		return 0, errors.New("no valid F2FS checkpoint")
	}
	start := cpAddress
	if okTwo && (!okOne || int64(versionTwo-versionOne) > 0) {
		start += segBlocks
	}
	checkpoint := make([]byte, (1+payload)*layout.blockSize)
	if _, err := file.ReadAt(checkpoint, int64(start*layout.blockSize)); err != nil {
		return 0, fmt.Errorf("read checkpoint: %w", err)
	}
	flags, total := le.Uint32(checkpoint[132:]), uint64(le.Uint32(checkpoint[136:]))
	summaryAddress := start + total - 4
	if flags&f2fsCPCompact != 0 {
		summaryAddress = start + uint64(le.Uint32(checkpoint[140:]))
	} else if flags&(f2fsCPUmount|f2fsCPFastboot) != 0 {
		summaryAddress = start + total - 7
	}
	summary, err := layout.block(summaryAddress)
	if err != nil {
		return 0, err
	}
	journal := summary
	if flags&f2fsCPCompact == 0 {
		journal = summary[7*layout.blockSize/8:]
	}
	var address uint32
	found := false
	count := int(le.Uint16(journal))
	if 2+13*count > len(journal) {
		return 0, errors.New("corrupt F2FS NAT journal")
	}
	for index := 0; index < count; index++ {
		item := journal[2+13*index:]
		if le.Uint32(item) == root {
			address, found = le.Uint32(item[9:]), true
		}
	}
	if !found {
		bitmapOffset := uint64(f2fsCPBitmap)
		if flags&f2fsCPLargeNAT != 0 {
			bitmapOffset += 4
		} else if payload == 0 {
			bitmapOffset += uint64(le.Uint32(checkpoint[156:]))
		}
		entries := uint64(layout.blockSize / 9)
		blockIndex := uint64(root) / entries
		if bitmapOffset+blockIndex/8 >= uint64(len(checkpoint)) {
			return 0, errors.New("F2FS NAT bitmap is inconsistent")
		}
		natBlock := natAddress + (blockIndex>>layout.logSegBlocks)<<layout.logSegBlocks<<1 + blockIndex&(segBlocks-1)
		if checkpoint[bitmapOffset+blockIndex/8]&(0x80>>(blockIndex&7)) != 0 {
			natBlock += segBlocks
		}
		nat, err := layout.block(natBlock)
		if err != nil {
			return 0, err
		}
		address = le.Uint32(nat[(uint64(root)%entries)*9+5:])
	}
	inode, err := layout.block(uint64(address))
	if err != nil {
		return 0, err
	}
	if le.Uint32(inode[layout.blockSize-24:]) != root {
		return 0, errors.New("F2FS root inode block does not match its node id")
	}
	return int64(le.Uint64(inode[48:])), nil
}
