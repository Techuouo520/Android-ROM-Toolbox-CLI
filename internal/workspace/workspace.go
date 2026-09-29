// Package workspace records how an unpacked ROM directory was produced so artb pack can rebuild it.
package workspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	FileName = ".artb-workspace.json"
	lockName = ".artb-workspace.lock"
	version  = 1
)

// LP metadata flags that lpmake reproduces; see liblp metadata_format.h.
const (
	HeaderFlagVirtualAB   = 0x1
	PartitionAttrReadonly = 0x1
)

type Workspace struct {
	Version    int                   `json:"version"`
	Super      *Super                `json:"super,omitempty"`
	Partitions map[string]*Partition `json:"partitions"`
}

type Super struct {
	Source   string   `json:"source"`
	Sparse   bool     `json:"sparse"`
	Metadata Metadata `json:"metadata"`
}

// Metadata mirrors lpunpack --artb-metadata output.
type Metadata struct {
	MajorVersion      uint32           `json:"major_version"`
	MinorVersion      uint32           `json:"minor_version"`
	HeaderFlags       uint32           `json:"header_flags"`
	MetadataMaxSize   uint32           `json:"metadata_max_size"`
	MetadataSlotCount uint32           `json:"metadata_slot_count"`
	LogicalBlockSize  uint32           `json:"logical_block_size"`
	BlockDevices      []BlockDevice    `json:"block_devices"`
	Groups            []Group          `json:"groups"`
	Partitions        []SuperPartition `json:"partitions"`
}

type BlockDevice struct {
	Name               string `json:"name"`
	Size               uint64 `json:"size"`
	FirstLogicalSector uint64 `json:"first_logical_sector"`
	Alignment          uint32 `json:"alignment"`
	AlignmentOffset    uint32 `json:"alignment_offset"`
	Flags              uint32 `json:"flags"`
}

type Group struct {
	Name        string `json:"name"`
	MaximumSize uint64 `json:"maximum_size"`
	Flags       uint32 `json:"flags"`
}

type SuperPartition struct {
	Name       string   `json:"name"`
	Group      string   `json:"group"`
	Attributes uint32   `json:"attributes"`
	Size       uint64   `json:"size"`
	Extents    []Extent `json:"extents"`
}

type Extent struct {
	NumSectors   uint64 `json:"num_sectors"`
	TargetType   uint32 `json:"target_type"`
	TargetData   uint64 `json:"target_data"`
	TargetSource uint32 `json:"target_source"`
}

type Partition struct {
	Image      string      `json:"image"`
	Source     string      `json:"source,omitempty"`
	Size       int64       `json:"size"`
	Sparse     bool        `json:"sparse,omitempty"`
	Filesystem *Filesystem `json:"filesystem,omitempty"`
	DeviceTree *DeviceTree `json:"device_tree,omitempty"`
}

// DeviceTree points at a DTBO or DTB image unpacked into a directory of dts files; its layout lives in the directory.
type DeviceTree struct {
	Dir         string `json:"dir"`
	Fingerprint string `json:"fingerprint"`
}

type Filesystem struct {
	Type         string       `json:"type"`
	Tree         string       `json:"tree"`
	FSConfig     string       `json:"fs_config"`
	FileContexts string       `json:"file_contexts"`
	UUID         string       `json:"uuid"`
	Label        string       `json:"label,omitempty"`
	Timestamp    int64        `json:"timestamp"`
	BlockSize    uint32       `json:"block_size"`
	EROFS        *EROFSParams `json:"erofs,omitempty"`
	EXT4         *EXT4Params  `json:"ext4,omitempty"`
	F2FS         *F2FSParams  `json:"f2fs,omitempty"`
	AVB          *AVBFooter   `json:"avb,omitempty"`
	Fingerprint  string       `json:"fingerprint"`
}

// AVBFooter keeps the image size and footer vbmeta that artb pack reuses to rebuild the dm-verity hashtree footer.
type AVBFooter struct {
	Size   int64  `json:"size"`
	VBMeta []byte `json:"vbmeta"`
}

type EROFSParams struct {
	Compression  string   `json:"compression,omitempty"`
	PclusterSize uint32   `json:"pcluster_size,omitempty"`
	Extended     []string `json:"extended,omitempty"`
}

type EXT4Params struct {
	BlockCount     uint64   `json:"block_count"`
	InodeCount     uint32   `json:"inode_count"`
	InodeSize      uint16   `json:"inode_size"`
	ReservedBlocks uint64   `json:"reserved_blocks"`
	BlocksPerGroup uint32   `json:"blocks_per_group"`
	FlexBGSize     uint32   `json:"flex_bg_size,omitempty"`
	Features       []string `json:"features"`
	SharedBlocks   bool     `json:"shared_blocks,omitempty"`
	HashSeed       string   `json:"hash_seed,omitempty"`
	HashSignedness string   `json:"hash_signedness,omitempty"`
	LastMounted    string   `json:"last_mounted,omitempty"`
	CreatedAt      int64    `json:"created_at"`
}

// F2FSParams keeps what mkfs.f2fs needs to lay out an equivalent volume; Version replaces the build host's kernel release.
type F2FSParams struct {
	BlockCount         uint64   `json:"block_count"`
	Features           []string `json:"features"`
	SegmentsPerSection uint32   `json:"segments_per_section,omitempty"`
	SectionsPerZone    uint32   `json:"sections_per_zone,omitempty"`
	Encoding           string   `json:"encoding,omitempty"`
	Version            string   `json:"version,omitempty"`
}

// Path resolves a slash-separated workspace path against root.
func Path(root, relative string) string {
	if filepath.IsAbs(relative) {
		return relative
	}
	return filepath.Join(root, filepath.FromSlash(relative))
}

// Relative stores target relative to root when it lives inside, otherwise as an absolute path.
func Relative(root, target string) string {
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return target
	}
	return filepath.ToSlash(relative)
}

// Exists reports whether dir holds a workspace file.
func Exists(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, FileName))
	return err == nil && info.Mode().IsRegular()
}

func Load(dir string) (*Workspace, error) {
	data, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		return nil, fmt.Errorf("read workspace: %w", err)
	}
	var workspace Workspace
	if err = json.Unmarshal(data, &workspace); err != nil {
		return nil, fmt.Errorf("parse workspace %q: %w", dir, err)
	}
	if workspace.Version != version {
		return nil, fmt.Errorf("workspace %q has unsupported version %d", dir, workspace.Version)
	}
	if workspace.Partitions == nil {
		workspace.Partitions = map[string]*Partition{}
	}
	return &workspace, nil
}

// Names lists partitions in a stable order.
func (workspace *Workspace) Names() []string {
	names := make([]string, 0, len(workspace.Partitions))
	for name := range workspace.Partitions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Update applies change under the workspace lock, creating the workspace when it does not exist yet.
func Update(ctx context.Context, dir string, change func(*Workspace) error) error {
	unlock, err := lock(ctx, dir)
	if err != nil {
		return err
	}
	workspace, err := Load(dir)
	if errors.Is(err, fs.ErrNotExist) {
		workspace, err = &Workspace{Version: version, Partitions: map[string]*Partition{}}, nil
	}
	if err == nil {
		err = change(workspace)
	}
	if err == nil {
		err = save(dir, workspace)
	}
	if unlockErr := unlock(); err == nil {
		err = unlockErr
	}
	return err
}

func save(dir string, workspace *Workspace) error {
	data, err := json.MarshalIndent(workspace, "", "  ")
	if err != nil {
		return fmt.Errorf("encode workspace: %w", err)
	}
	temporary := filepath.Join(dir, FileName+".tmp")
	if err = os.WriteFile(temporary, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write workspace: %w", err)
	}
	if err = os.Rename(temporary, filepath.Join(dir, FileName)); err != nil {
		return fmt.Errorf("replace workspace: %w", err)
	}
	return nil
}

// lock serializes concurrent artb processes that register partitions in the same workspace.
func lock(ctx context.Context, dir string) (func() error, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create workspace: %w", err)
	}
	path := filepath.Join(dir, lockName)
	deadline := time.Now().Add(2 * time.Minute)
	var deniedSince time.Time
	for {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			if closeErr := file.Close(); closeErr != nil {
				return nil, fmt.Errorf("lock workspace: %w", closeErr)
			}
			return func() error {
				if removeErr := os.Remove(path); removeErr != nil {
					return fmt.Errorf("unlock workspace: %w", removeErr)
				}
				return nil
			}, nil
		}
		// Windows reports a lock file another writer is still deleting as access denied; that clears within milliseconds, a real denial does not.
		deletePending := runtime.GOOS == "windows" && errors.Is(err, fs.ErrPermission)
		if !deletePending {
			deniedSince = time.Time{}
		}
		switch {
		case deletePending:
			if deniedSince.IsZero() {
				deniedSince = time.Now()
			} else if time.Since(deniedSince) > 2*time.Second {
				return nil, fmt.Errorf("lock workspace: %w", err)
			}
		case !errors.Is(err, fs.ErrExist):
			return nil, fmt.Errorf("lock workspace: %w", err)
		default:
			// A lock older than any registration step was left by a killed process.
			if info, statErr := os.Stat(path); statErr == nil && time.Since(info.ModTime()) > 10*time.Minute {
				if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
					return nil, fmt.Errorf("remove stale workspace lock: %w", removeErr)
				}
				continue
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("workspace %q is locked by another artb process; remove %s if none is running", dir, path)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}
