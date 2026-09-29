package cli

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"artb/internal/avb"
	"artb/internal/bootimg"
	"artb/internal/detect"
	"artb/internal/dtbo"
	"artb/internal/fdt"
)

// deviceTreeImage is a file that carries device trees: a dtb blob, a DTBO table or the dtb section of a boot image.
type deviceTreeImage struct {
	path   string
	kind   detect.Type
	data   []byte
	boot   *bootimg.Image
	bootID string
	table  *dtbo.Header
	footer *avb.Raw
	trees  []*deviceTree
}

// deviceTree is one tree of a deviceTreeImage; Offset is its absolute position in data, or -1 for a compressed payload.
type deviceTree struct {
	Index  int
	Offset int
	Blob   []byte
	Tree   *fdt.Tree
	Entry  *dtbo.Entry
	Region string
}

// loadDeviceTreeImage reads path fully and parses every device tree it holds; images without trees get an empty list.
func loadDeviceTreeImage(path string) (*deviceTreeImage, error) {
	result, err := detect.File(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	image := &deviceTreeImage{path: path, kind: result.Type, data: data}
	limit := len(data)
	if raw, err := avb.ReadRaw(path); err == nil && raw.Footer != nil {
		image.footer = raw
		limit = int(min(raw.Footer.OriginalImageSize, uint64(len(data))))
	}
	switch result.Type {
	case detect.Boot, detect.VendorBoot:
		if image.boot, err = bootimg.Parse(data[:limit]); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		image.bootID = image.boot.IDAlgorithm(data)
		if section, ok := image.boot.Section("dtb"); ok && section.Size > 0 {
			if err = image.addBlobs(int(section.Offset), data[section.Offset:section.Offset+section.Size], "dtb"); err != nil {
				return nil, err
			}
		}
	case detect.DTB:
		if err = image.addBlobs(0, data[:limit], "dtb"); err != nil {
			return nil, err
		}
	case detect.DTBO:
		header, entries, err := dtbo.Parse(data[:limit])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		image.table = &header
		for index := range entries {
			entry := &entries[index]
			payload := data[entry.Offset : entry.Offset+entry.Size]
			tree := &deviceTree{Index: index, Offset: int(entry.Offset), Blob: payload, Entry: entry, Region: "dtbo"}
			if compression := entry.Compression(header.Version); compression != dtbo.NoCompression {
				if tree.Blob, err = dtbo.Decompress(payload, compression); err != nil {
					return nil, fmt.Errorf("%s entry %d: %w", path, index, err)
				}
				tree.Offset = -1
			}
			if tree.Tree, err = fdt.Parse(tree.Blob); err != nil {
				return nil, fmt.Errorf("%s entry %d: %w", path, index, err)
			}
			image.trees = append(image.trees, tree)
		}
	}
	return image, nil
}

func (image *deviceTreeImage) addBlobs(base int, region []byte, name string) error {
	segments, err := fdt.Split(region)
	if err != nil {
		return fmt.Errorf("%s %s: %w", image.path, name, err)
	}
	offset := base
	for _, segment := range segments {
		if segment.Blob {
			tree, err := fdt.Parse(segment.Data)
			if err != nil {
				return fmt.Errorf("%s tree %d: %w", image.path, len(image.trees), err)
			}
			image.trees = append(image.trees, &deviceTree{Index: len(image.trees), Offset: offset, Blob: segment.Data, Tree: tree, Region: name})
		}
		offset += len(segment.Data)
	}
	return nil
}

// selectTrees returns the trees named by indexes, or all trees when indexes is empty.
func (image *deviceTreeImage) selectTrees(indexes []int) ([]*deviceTree, error) {
	if len(image.trees) == 0 {
		return nil, fmt.Errorf("%s holds no device trees", image.path)
	}
	if len(indexes) == 0 {
		return image.trees, nil
	}
	var selected []*deviceTree
	for _, index := range indexes {
		if index < 0 || index >= len(image.trees) {
			return nil, fmt.Errorf("%s has trees 0-%d, not %d", image.path, len(image.trees)-1, index)
		}
		selected = append(selected, image.trees[index])
	}
	return selected, nil
}

// treeEdit replaces the value of one property with bytes of the same length.
type treeEdit struct {
	tree     *deviceTree
	node     *fdt.Node
	property *fdt.Property
	value    []byte
}

func (edit treeEdit) check() error {
	if edit.tree.Offset < 0 {
		return fmt.Errorf("tree %d is stored compressed, so it cannot be edited in place", edit.tree.Index)
	}
	if len(edit.value) != len(edit.property.Value) {
		return fmt.Errorf("tree %d %s %s: new value is %d bytes but the property holds %d; in-place edits keep the length (use artb dtb unpack and pack to resize)", edit.tree.Index, edit.node.Path, edit.property.Name, len(edit.value), len(edit.property.Value))
	}
	return nil
}

// apply copies the edits into image.data; the parsed values alias data, so they change too.
func (image *deviceTreeImage) apply(edits []treeEdit) error {
	for _, edit := range edits {
		if err := edit.check(); err != nil {
			return err
		}
	}
	for _, edit := range edits {
		copy(image.data[edit.tree.Offset+edit.property.Offset:], edit.value)
	}
	return nil
}

// patchedName is the default output: <name>_patched<ext> beside the input.
func patchedName(path string) string {
	extension := filepath.Ext(path)
	return path[:len(path)-len(extension)] + "_patched" + extension
}

// sameFile reports whether output would overwrite input.
func sameFile(input, output string) (bool, error) {
	if filepath.Clean(input) == filepath.Clean(output) {
		return true, nil
	}
	inputInfo, err := os.Stat(input)
	if err != nil {
		return false, err
	}
	outputInfo, err := os.Stat(output)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return os.SameFile(inputInfo, outputInfo), nil
}

// checkOutput refuses to write over an input and, unless force is set, over any existing file.
func checkOutput(output string, force bool, inputs ...string) error {
	for _, input := range inputs {
		same, err := sameFile(input, output)
		if err != nil {
			return err
		}
		if same {
			return fmt.Errorf("output %s is an input image; choose another path", output)
		}
	}
	if _, err := os.Stat(output); err == nil && !force {
		return fmt.Errorf("output %s already exists; pass --force to replace it or choose another -o", output)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// write stores the edited image at output, refreshing the v0-v2 boot id and the AVB hash footer; the input is never touched.
func (image *deviceTreeImage) write(output string, key *rsa.PrivateKey, force bool) (*avb.FooterResult, error) {
	err := checkOutput(output, force, image.path)
	if err != nil {
		return nil, err
	}
	if image.boot != nil && image.bootID != "" {
		image.boot.UpdateID(image.data, image.bootID)
	}
	if err = os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return nil, err
	}
	temporary := output + ".artb-tmp"
	if err = os.WriteFile(temporary, image.data, 0o644); err != nil {
		return nil, err
	}
	var footer *avb.FooterResult
	if image.footer != nil {
		meta, parseErr := avb.Parse(image.footer.Blob)
		if parseErr == nil && slices.ContainsFunc(meta.Descriptors, func(descriptor avb.Descriptor) bool { return descriptor.Kind == "hash" }) {
			if footer, err = avb.UpdateHashFooter(temporary, key); err != nil {
				os.Remove(temporary)
				return nil, err
			}
		}
	}
	if err = moveFile(temporary, output); err != nil {
		return nil, err
	}
	return footer, nil
}
