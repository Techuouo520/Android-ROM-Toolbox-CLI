package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"artb/internal/avb"
	"artb/internal/fsinfo"
	"artb/internal/fsmeta"
	"artb/internal/workspace"
)

// partitionOutput extracts into the workspace that holds the image, otherwise into <name>_unpacked next to it.
func partitionOutput(options unpackOptions, inputPath string) (string, error) {
	if options.output != "" {
		path, err := filepath.Abs(options.output)
		if err != nil {
			return "", fmt.Errorf("resolve output %q: %w", options.output, err)
		}
		return path, nil
	}
	source := inputPath
	if options.source != "" {
		source = options.source
	}
	if directory := filepath.Dir(source); workspace.Exists(directory) {
		return directory, nil
	}
	return defaultOutput(source), nil
}

func imageName(path string) string {
	return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
}

// ensureFreshTree refuses to extract over an existing tree so a second unpack never mixes with edits.
func ensureFreshTree(root, name string) error {
	tree := filepath.Join(root, name)
	entries, err := os.ReadDir(tree)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %q: %w", tree, err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("%q already holds an unpacked tree; remove it to unpack again", tree)
	}
	return nil
}

// registerFilesystem records the tree, configs and superblock parameters so artb pack can rebuild the image.
func registerFilesystem(ctx context.Context, root, kind, rawPath string, options unpackOptions) error {
	name := imageName(rawPath)
	record := &workspace.Filesystem{Type: kind, Tree: name, FSConfig: "config/" + name + "_fs_config", FileContexts: "config/" + name + "_file_contexts"}
	switch kind {
	case "erofs":
		info, err := fsinfo.ReadEROFS(rawPath)
		if err != nil {
			return err
		}
		params := info.Params
		record.UUID, record.Label, record.Timestamp, record.BlockSize, record.EROFS = info.UUID, info.Label, info.Timestamp, info.BlockSize, &params
	case "ext4":
		info, err := fsinfo.ReadEXT4(rawPath)
		if err != nil {
			return err
		}
		params := info.Params
		record.UUID, record.Label, record.Timestamp, record.BlockSize, record.EXT4 = info.UUID, info.Label, info.Timestamp, info.BlockSize, &params
	case "f2fs":
		info, err := fsinfo.ReadF2FS(rawPath)
		if err != nil {
			return err
		}
		params := info.Params
		record.UUID, record.Label, record.Timestamp, record.BlockSize, record.F2FS = info.UUID, info.Label, info.Timestamp, info.BlockSize, &params
	default:
		return fmt.Errorf("unsupported filesystem %q", kind)
	}
	entries, err := fsmeta.Scan(workspace.Path(root, record.Tree))
	if err != nil {
		return err
	}
	if record.Fingerprint, err = fsmeta.Fingerprint(entries, workspace.Path(root, record.FSConfig), workspace.Path(root, record.FileContexts)); err != nil {
		return err
	}
	info, err := os.Stat(rawPath)
	if err != nil {
		return fmt.Errorf("stat %q: %w", rawPath, err)
	}
	record.AVB = hashtreeFooter(rawPath, info.Size())
	source := rawPath
	if options.source != "" {
		source = options.source
	}
	return workspace.Update(ctx, root, func(current *workspace.Workspace) error {
		partition := current.Partitions[name]
		if partition == nil {
			partition = &workspace.Partition{}
			current.Partitions[name] = partition
		}
		partition.Image, partition.Sparse, partition.Source = workspace.Relative(root, source), options.sparse, ""
		// Images outside the workspace stay untouched; pack writes a new one inside it.
		if filepath.IsAbs(partition.Image) {
			partition.Image, partition.Sparse, partition.Source = name+".img", false, source
		}
		partition.Size, partition.Filesystem = info.Size(), record
		return nil
	})
}

// hashtreeFooter returns the footer vbmeta of an image that carries an AVB hashtree footer, or nil.
func hashtreeFooter(path string, size int64) *workspace.AVBFooter {
	raw, err := avb.ReadRaw(path)
	if err != nil || raw.Footer == nil {
		return nil
	}
	meta, err := avb.Parse(raw.Blob)
	if err != nil {
		return nil
	}
	for _, descriptor := range meta.Descriptors {
		if descriptor.Kind == "hashtree" {
			return &workspace.AVBFooter{Size: size, VBMeta: raw.Blob}
		}
	}
	return nil
}

// registerSuper stores the LP layout from lpunpack and the partition images it wrote.
func registerSuper(ctx context.Context, root, source string, sparse bool, metadataPath string) error {
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return fmt.Errorf("read super metadata: %w", err)
	}
	var metadata workspace.Metadata
	if err = json.Unmarshal(data, &metadata); err != nil {
		return fmt.Errorf("parse super metadata: %w", err)
	}
	return workspace.Update(ctx, root, func(current *workspace.Workspace) error {
		current.Super = &workspace.Super{Source: filepath.Base(source), Sparse: sparse, Metadata: metadata}
		for _, partition := range metadata.Partitions {
			info, err := os.Stat(filepath.Join(root, partition.Name+".img"))
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return fmt.Errorf("stat partition image %s: %w", partition.Name, err)
			}
			record := current.Partitions[partition.Name]
			if record == nil {
				record = &workspace.Partition{}
				current.Partitions[partition.Name] = record
			}
			record.Image, record.Size, record.Sparse, record.Source = partition.Name+".img", info.Size(), false, ""
		}
		return nil
	})
}

// registerImages records payload partitions so later unpacks and packs share one workspace.
func registerImages(ctx context.Context, root string, names []string) error {
	return workspace.Update(ctx, root, func(current *workspace.Workspace) error {
		for _, name := range names {
			info, err := os.Stat(filepath.Join(root, name+".img"))
			if err != nil {
				return fmt.Errorf("stat partition image %s: %w", name, err)
			}
			record := current.Partitions[name]
			if record == nil {
				record = &workspace.Partition{}
				current.Partitions[name] = record
			}
			record.Image, record.Size = name+".img", info.Size()
		}
		return nil
	})
}
