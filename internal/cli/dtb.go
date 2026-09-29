package cli

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"artb/internal/avb"
	"artb/internal/buildinfo"
	"artb/internal/cpu"
	"artb/internal/detect"
	"artb/internal/dtbo"
	"artb/internal/executor"
	"artb/internal/fdt"
	"artb/internal/fsmeta"
	"artb/internal/nativebin"
	"artb/internal/workspace"

	"github.com/spf13/cobra"
)

const deviceTreeMetadataName = ".artb-dt.json"

// deviceTreeEntry is one overlay of a DTBO table or one segment of a concatenated DTB file.
type deviceTreeEntry struct {
	Name    string    `json:"name,omitempty"`
	ID      uint32    `json:"id,omitempty"`
	Rev     uint32    `json:"rev,omitempty"`
	Custom  [4]uint32 `json:"custom,omitempty"`
	Offset  uint32    `json:"offset,omitempty"`
	Gap     uint32    `json:"gap,omitempty"`
	Raw     []byte    `json:"raw,omitempty"`
	DTS     string    `json:"dts_sha256,omitempty"`
	DTB     string    `json:"dtb_sha256,omitempty"`
	Stored  string    `json:"stored_sha256,omitempty"`
	Symbols bool      `json:"symbols,omitempty"`
	BootCPU uint32    `json:"boot_cpuid,omitempty"`
}

// deviceTreeMetadata records everything needed to rebuild the original container byte for byte from the directory.
type deviceTreeMetadata struct {
	Version int                  `json:"version"`
	Kind    string               `json:"kind"`
	Source  string               `json:"source"`
	Table   *dtbo.Header         `json:"table,omitempty"`
	PadTo   int64                `json:"pad_to,omitempty"`
	AVB     *workspace.AVBFooter `json:"avb,omitempty"`
	Entries []deviceTreeEntry    `json:"entries"`
}

func newDTBOCommand() *cobra.Command {
	unpack, _ := newFormatUnpackCommand(detect.DTBO, "unpack <dtbo.img>", "Split a DTBO image into overlays decompiled to dts", "  artb dtbo unpack dtbo.img\n  artb dtbo unpack dtbo.img -o dtbo_unpacked", false, true)
	return newGroupCommand("dtbo", "Unpack, pack and apply Android DTBO overlay images", unpack, newDeviceTreePackCommand("dtbo"), newDTBOApplyCommand())
}

func newDTBCommand() *cobra.Command {
	unpack, _ := newFormatUnpackCommand(detect.DTB, "unpack <dtb>", "Split one or more concatenated device trees and decompile them to dts", "  artb dtb unpack vendor_boot_unpacked/dtb\n  artb dtb unpack kernel.dtb -o dtb_unpacked", false, true)
	return newGroupCommand("dtb", "Unpack, pack, query and patch device tree blobs", unpack, newDeviceTreePackCommand("dtb"), newDTBQueryCommand(), newDTBSetCommand(), newDTBPatchCommand(), newDTBMatchCommand())
}

func newDeviceTreePackCommand(kind string) *cobra.Command {
	var output, keyPath string
	var quiet bool
	cmd := &cobra.Command{Use: "pack <unpacked-dir>", Short: "Rebuild the " + kind + " image from an unpacked directory", Long: "Rebuild the " + kind + " image. The .dts files sit at the top of the directory and the binaries in its dtb folder. Entries whose .dts and dtb/*.dtb are untouched keep their original bytes, an edited .dts is compiled with dtc and an edited dtb/*.dtb is used as is. An AVB hash footer from the original image is recomputed; copy the new descriptor into vbmeta.img with artb vbmeta sync.", Example: "  artb " + kind + " pack " + kind + "_unpacked\n  artb " + kind + " pack " + kind + "_unpacked -o " + kind + "_new.img", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Root().SilenceUsage = true
		started := time.Now()
		dir, err := filepath.Abs(args[0])
		if err != nil {
			return fmt.Errorf("resolve directory %q: %w", args[0], err)
		}
		var key *rsa.PrivateKey
		if keyPath != "" {
			if key, err = avb.LoadKey(keyPath); err != nil {
				return err
			}
		}
		meta, err := readDeviceTreeMetadata(dir)
		if err != nil {
			return err
		}
		if output == "" {
			output = filepath.Join(filepath.Dir(dir), strings.TrimSuffix(meta.Source, filepath.Ext(meta.Source))+"_repacked"+filepath.Ext(meta.Source))
		}
		if output, err = filepath.Abs(output); err != nil {
			return err
		}
		result, err := packDeviceTree(cmd.Context(), dir, output, key, false, cpu.Logical())
		if err != nil || quiet {
			return err
		}
		text := fmt.Sprintf("%s\ncompiled %d of %d\n", output, result.compiled, result.trees)
		if result.footer != nil {
			meta, err := avb.Read(output)
			if err != nil {
				return err
			}
			for _, descriptor := range meta.Descriptors {
				if descriptor.Kind == "hash" {
					text += fmt.Sprintf("avb %s image_size=%d digest=%s\n", descriptor.Partition, descriptor.ImageSize, descriptor.Digest)
				}
			}
			if result.footer.StaleSignature {
				fmt.Fprintf(cmd.ErrOrStderr(), "%s: the AVB footer signature no longer matches; pass --avb-key to re-sign it\n", output)
			}
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "%selapsed %.3fs\n", text, time.Since(started).Seconds())
		return err
	}}
	cmd.Flags().StringVarP(&output, "output", "o", "", "Set output image path (default: <source>_repacked next to the directory)")
	cmd.Flags().StringVar(&keyPath, "avb-key", "", "Re-sign a signed AVB footer with this RSA private key (PEM)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress success output")
	return cmd
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// runDTC feeds input to dtc on stdin inside dir, so /include/ resolves next to the dts files and paths stay ASCII.
func runDTC(ctx context.Context, executable, dir string, input []byte, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	if _, err := executor.New(1).Run(ctx, executor.Spec{Name: executable, Args: append(args, "-"), Dir: dir, Stdin: bytes.NewReader(input), Stdout: &stdout, Stderr: &stderr}); err != nil {
		return nil, fmt.Errorf("dtc: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// parallelDeviceTrees runs work for indexes 0..count-1 on up to workers goroutines and returns the first error.
func parallelDeviceTrees(count, workers int, work func(int) error) error {
	var next atomic.Int64
	var group sync.WaitGroup
	errs := make([]error, count)
	for range min(max(workers, 1), max(count, 1)) {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := int(next.Add(1)) - 1; index < count; index = int(next.Add(1)) - 1 {
				errs[index] = work(index)
			}
		}()
	}
	group.Wait()
	return errors.Join(errs...)
}

func entryName(index, count int) string {
	return fmt.Sprintf("%0*d", max(2, len(fmt.Sprint(max(count-1, 0)))), index)
}

func unpackDeviceTree(ctx context.Context, cmd *cobra.Command, inputPath string, kind detect.Type, options unpackOptions) error {
	started := time.Now()
	root, dir := "", options.output
	if dir == "" {
		if parent := filepath.Dir(inputPath); workspace.Exists(parent) {
			root, dir = parent, filepath.Join(parent, imageName(inputPath))
		} else {
			dir = defaultOutput(inputPath)
		}
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve output %q: %w", dir, err)
	}
	if err = createEmptyDir(dir); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Join(dir, deviceTreeBlobDir), 0o755); err != nil {
		return err
	}
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	meta := deviceTreeMetadata{Version: 1, Kind: "dtb", Source: filepath.Base(inputPath)}
	if raw, err := avb.ReadRaw(inputPath); err == nil && raw.Footer != nil && raw.Footer.OriginalImageSize <= uint64(len(data)) {
		meta.AVB = &workspace.AVBFooter{Size: int64(len(data)), VBMeta: raw.Blob}
		data = data[:raw.Footer.OriginalImageSize]
	}
	trees := map[string][]byte{}
	if kind == detect.DTBO {
		meta.Kind = "dtbo"
		header, entries, err := dtbo.Parse(data)
		if err != nil {
			return fmt.Errorf("%s: %w", inputPath, err)
		}
		meta.Table = &header
		if meta.AVB == nil && int64(len(data)) > int64(header.TotalSize) {
			meta.PadTo = int64(len(data))
		}
		offsets := make([]uint32, 0, len(entries))
		ends := map[uint32]uint32{}
		for _, entry := range entries {
			if _, seen := ends[entry.Offset]; !seen {
				offsets = append(offsets, entry.Offset)
			}
			ends[entry.Offset] = max(ends[entry.Offset], entry.Offset+entry.Size)
		}
		slices.Sort(offsets)
		gaps := map[uint32]uint32{}
		for index, offset := range offsets {
			next := header.TotalSize
			if index+1 < len(offsets) {
				next = offsets[index+1]
			}
			if next < ends[offset] {
				return fmt.Errorf("%s: DTBO payloads overlap", inputPath)
			}
			gaps[offset] = next - ends[offset]
		}
		for index, entry := range entries {
			name := entryName(index, len(entries))
			payload := data[entry.Offset : entry.Offset+entry.Size]
			record := deviceTreeEntry{Name: name, ID: entry.ID, Rev: entry.Rev, Custom: entry.Custom, Offset: entry.Offset, Gap: gaps[entry.Offset]}
			delete(gaps, entry.Offset)
			tree, err := dtbo.Decompress(payload, entry.Compression(header.Version))
			if err != nil {
				return fmt.Errorf("%s entry %s: %w", inputPath, name, err)
			}
			if compression := entry.Compression(header.Version); compression != dtbo.NoCompression {
				if err = os.WriteFile(storedPath(dir, name, compression), payload, 0o644); err != nil {
					return err
				}
				record.Stored = sha256Hex(payload)
			}
			trees[name] = tree
			meta.Entries = append(meta.Entries, record)
		}
	} else {
		segments, err := fdt.Split(data)
		if err != nil {
			return fmt.Errorf("%s: %w", inputPath, err)
		}
		blobs := 0
		for _, segment := range segments {
			if segment.Blob {
				blobs++
			}
		}
		index := 0
		for _, segment := range segments {
			if !segment.Blob {
				meta.Entries = append(meta.Entries, deviceTreeEntry{Raw: segment.Data})
				continue
			}
			name := entryName(index, blobs)
			index++
			trees[name] = segment.Data
			meta.Entries = append(meta.Entries, deviceTreeEntry{Name: name})
		}
	}
	executable, err := nativebin.New(buildinfo.Version).Ensure(ctx, "dtc")
	if err != nil {
		return err
	}
	var named []int
	for index, entry := range meta.Entries {
		if entry.Name != "" {
			named = append(named, index)
		}
	}
	// Decompile each distinct tree once; overlays that shared a payload get the same dts.
	sources := map[string][]byte{}
	var sourcesMutex sync.Mutex
	err = parallelDeviceTrees(len(named), options.jobs, func(position int) error {
		entry := &meta.Entries[named[position]]
		tree := trees[entry.Name]
		header, err := fdt.ParseHeader(tree)
		if err != nil {
			return fmt.Errorf("%s entry %s: %w", inputPath, entry.Name, err)
		}
		nodes, err := fdt.RootNodes(tree)
		if err != nil {
			return fmt.Errorf("%s entry %s: %w", inputPath, entry.Name, err)
		}
		entry.Symbols, entry.BootCPU = slices.Contains(nodes, "__symbols__"), header.BootCPUID
		key := sha256Hex(tree)
		sourcesMutex.Lock()
		source, ok := sources[key]
		sourcesMutex.Unlock()
		if !ok {
			if source, err = runDTC(ctx, executable, dir, tree, "-I", "dtb", "-O", "dts", "-q"); err != nil {
				return fmt.Errorf("decompile %s entry %s: %w", inputPath, entry.Name, err)
			}
			sourcesMutex.Lock()
			sources[key] = source
			sourcesMutex.Unlock()
		}
		entry.DTS, entry.DTB = sha256Hex(source), key
		if err = os.WriteFile(blobPath(dir, entry.Name), tree, 0o644); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, entry.Name+".dts"), source, 0o644)
	})
	if err != nil {
		return err
	}
	if err = writeDeviceTreeMetadata(dir, meta); err != nil {
		return err
	}
	if root != "" {
		if err = registerDeviceTree(ctx, root, imageName(inputPath), inputPath, dir); err != nil {
			return err
		}
	}
	if options.quiet {
		return nil
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\ntrees %d\nelapsed %.3fs\n", dir, len(named), time.Since(started).Seconds())
	return err
}

// Binaries sit in a dtb folder beside the editable dts files: NN.dtb for each tree, NN.zlib or NN.gz for original compressed payloads.
const deviceTreeBlobDir = "dtb"

func blobPath(dir, name string) string { return filepath.Join(dir, deviceTreeBlobDir, name+".dtb") }

func storedPath(dir, name string, compression uint32) string {
	if compression == dtbo.GzipCompression {
		return filepath.Join(dir, deviceTreeBlobDir, name+".gz")
	}
	return filepath.Join(dir, deviceTreeBlobDir, name+".zlib")
}

func readDeviceTreeMetadata(dir string) (deviceTreeMetadata, error) {
	var meta deviceTreeMetadata
	data, err := os.ReadFile(filepath.Join(dir, deviceTreeMetadataName))
	if err != nil {
		return meta, fmt.Errorf("read device tree metadata: %w", err)
	}
	if err = json.Unmarshal(data, &meta); err != nil {
		return meta, fmt.Errorf("parse device tree metadata: %w", err)
	}
	if meta.Version != 1 || (meta.Kind == "dtbo" && meta.Table == nil) || (meta.Kind != "dtbo" && meta.Kind != "dtb") {
		return meta, fmt.Errorf("unsupported device tree metadata in %q", dir)
	}
	return meta, nil
}

func writeDeviceTreeMetadata(dir string, meta deviceTreeMetadata) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, deviceTreeMetadataName), append(data, '\n'), 0o644)
}

// deviceTreeFingerprint lets artb pack skip a device tree directory whose files did not change.
func deviceTreeFingerprint(dir string) (string, error) {
	entries, err := fsmeta.Scan(dir)
	if err != nil {
		return "", err
	}
	return fsmeta.Fingerprint(entries)
}

func registerDeviceTree(ctx context.Context, root, name, image, dir string) error {
	fingerprint, err := deviceTreeFingerprint(dir)
	if err != nil {
		return err
	}
	info, err := os.Stat(image)
	if err != nil {
		return err
	}
	return workspace.Update(ctx, root, func(current *workspace.Workspace) error {
		partition := current.Partitions[name]
		if partition == nil {
			partition = &workspace.Partition{Image: workspace.Relative(root, image), Size: info.Size()}
			current.Partitions[name] = partition
		}
		partition.DeviceTree = &workspace.DeviceTree{Dir: workspace.Relative(root, dir), Fingerprint: fingerprint}
		return nil
	})
}

// packDeviceTrees rebuilds the workspace DTBO and DTB images whose unpacked directories changed since the last pack.
func packDeviceTrees(ctx context.Context, root string, current *workspace.Workspace, names []string, force, noAVB bool, key *rsa.PrivateKey) (map[string]deviceTreeResult, []string, error) {
	results := map[string]deviceTreeResult{}
	var unchanged []string
	for _, name := range names {
		partition := current.Partitions[name]
		dir := workspace.Path(root, partition.DeviceTree.Dir)
		// An image outside the workspace stays untouched; the rebuilt one lands inside it.
		image := partition.Image
		if filepath.IsAbs(image) {
			image = name + filepath.Ext(image)
		}
		output := workspace.Path(root, image)
		fingerprint, err := deviceTreeFingerprint(dir)
		if err != nil {
			return nil, nil, err
		}
		if _, statErr := os.Stat(output); !force && statErr == nil && fingerprint == partition.DeviceTree.Fingerprint {
			unchanged = append(unchanged, name)
			continue
		}
		result, err := packDeviceTree(ctx, dir, output, key, noAVB, cpu.Logical())
		if err != nil {
			return nil, nil, fmt.Errorf("pack %s: %w", name, err)
		}
		if fingerprint, err = deviceTreeFingerprint(dir); err != nil {
			return nil, nil, err
		}
		info, err := os.Stat(output)
		if err != nil {
			return nil, nil, err
		}
		err = workspace.Update(ctx, root, func(latest *workspace.Workspace) error {
			record := latest.Partitions[name]
			if record == nil || record.DeviceTree == nil {
				return fmt.Errorf("partition %q vanished from workspace", name)
			}
			record.Image, record.Size, record.DeviceTree.Fingerprint = image, info.Size(), fingerprint
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
		results[name] = result
	}
	return results, unchanged, nil
}

type deviceTreeResult struct {
	trees, compiled int
	footer          *avb.FooterResult
	elapsed         time.Duration
}

// packDeviceTree rebuilds the container described by dir into output, compiling edited dts files on all workers.
func packDeviceTree(ctx context.Context, dir, output string, key *rsa.PrivateKey, noAVB bool, workers int) (deviceTreeResult, error) {
	started := time.Now()
	var result deviceTreeResult
	meta, err := readDeviceTreeMetadata(dir)
	if err != nil {
		return result, err
	}
	executable, err := nativebin.New(buildinfo.Version).Ensure(ctx, "dtc")
	if err != nil {
		return result, err
	}
	trees := make([][]byte, len(meta.Entries))
	var compiled atomic.Int64
	err = parallelDeviceTrees(len(meta.Entries), workers, func(index int) error {
		entry := &meta.Entries[index]
		if entry.Name == "" {
			return nil
		}
		source, err := os.ReadFile(filepath.Join(dir, entry.Name+".dts"))
		if err != nil {
			return err
		}
		tree, err := os.ReadFile(blobPath(dir, entry.Name))
		if err != nil && !(errors.Is(err, fs.ErrNotExist) && sha256Hex(source) != entry.DTS) {
			return err
		}
		if sha256Hex(source) != entry.DTS {
			args := []string{"-I", "dts", "-O", "dtb", "-q"}
			if entry.Symbols {
				args = append(args, "-@")
			}
			if entry.BootCPU != 0 {
				args = append(args, "-b", fmt.Sprint(entry.BootCPU))
			}
			if tree, err = runDTC(ctx, executable, dir, source, args...); err != nil {
				return fmt.Errorf("compile %s.dts: %w", entry.Name, err)
			}
			if err = os.WriteFile(blobPath(dir, entry.Name), tree, 0o644); err != nil {
				return err
			}
			entry.DTS = sha256Hex(source)
			compiled.Add(1)
		}
		if _, err = fdt.ParseHeader(tree); err != nil {
			return fmt.Errorf("%s.dtb: %w", entry.Name, err)
		}
		trees[index] = tree
		return nil
	})
	if err != nil {
		return result, err
	}
	var image []byte
	if meta.Kind == "dtbo" {
		if image, err = layoutDTBO(dir, &meta, trees); err != nil {
			return result, err
		}
	} else {
		for index, entry := range meta.Entries {
			if entry.Name == "" {
				image = append(image, entry.Raw...)
				continue
			}
			image = append(image, trees[index]...)
			meta.Entries[index].DTB = sha256Hex(trees[index])
		}
	}
	if int64(len(image)) < meta.PadTo {
		image = append(image, make([]byte, meta.PadTo-int64(len(image)))...)
	}
	if err = os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return result, err
	}
	temporary := output + ".artb-tmp"
	if err = os.WriteFile(temporary, image, 0o644); err != nil {
		return result, err
	}
	if meta.AVB != nil && !noAVB {
		if result.footer, err = avb.AddHashFooter(temporary, meta.AVB.VBMeta, meta.AVB.Size, key); err != nil {
			os.Remove(temporary)
			return result, fmt.Errorf("add AVB hash footer: %w", err)
		}
	}
	if err = moveFile(temporary, output); err != nil {
		return result, err
	}
	if err = writeDeviceTreeMetadata(dir, meta); err != nil {
		return result, err
	}
	for _, entry := range meta.Entries {
		if entry.Name != "" {
			result.trees++
		}
	}
	result.compiled, result.elapsed = int(compiled.Load()), time.Since(started)
	return result, nil
}

// layoutDTBO writes the table and payloads in their original order and gaps; entries that shared a payload keep
// sharing it while their trees stay identical, and untouched compressed entries reuse their stored payload.
func layoutDTBO(dir string, meta *deviceTreeMetadata, trees [][]byte) ([]byte, error) {
	header := *meta.Table
	payloads := make([][]byte, len(meta.Entries))
	for index := range meta.Entries {
		entry := &meta.Entries[index]
		compression := dtbo.Entry{Custom: entry.Custom}.Compression(header.Version)
		payload := trees[index]
		if compression != dtbo.NoCompression {
			stored, err := os.ReadFile(storedPath(dir, entry.Name, compression))
			if err == nil && sha256Hex(stored) == entry.Stored && sha256Hex(trees[index]) == entry.DTB {
				payload = stored
			} else if payload, err = dtbo.Compress(trees[index], compression); err != nil {
				return nil, err
			}
		}
		entry.DTB = sha256Hex(trees[index])
		payloads[index] = payload
	}
	order := make([]int, len(meta.Entries))
	for index := range order {
		order[index] = index
	}
	sort.SliceStable(order, func(a, b int) bool { return meta.Entries[order[a]].Offset < meta.Entries[order[b]].Offset })
	start := uint32(len(meta.Entries)) * header.EntrySize
	start += header.EntriesOffset
	if len(order) > 0 {
		start = max(start, meta.Entries[order[0]].Offset)
	}
	body := []byte{}
	placed := map[uint32][]int{}
	entries := make([]dtbo.Entry, len(meta.Entries))
	cursor := start
	for _, index := range order {
		entry := meta.Entries[index]
		shared := -1
		for _, other := range placed[entry.Offset] {
			if bytes.Equal(payloads[other], payloads[index]) {
				shared = other
				break
			}
		}
		entries[index] = dtbo.Entry{Size: uint32(len(payloads[index])), ID: entry.ID, Rev: entry.Rev, Custom: entry.Custom}
		if shared >= 0 {
			entries[index].Offset = entries[shared].Offset
			continue
		}
		entries[index].Offset = cursor
		body = append(body, payloads[index]...)
		gap := uint32(0)
		if len(placed[entry.Offset]) == 0 {
			gap = entry.Gap
		}
		body = append(body, make([]byte, gap)...)
		cursor += uint32(len(payloads[index])) + gap
		placed[entry.Offset] = append(placed[entry.Offset], index)
	}
	header.TotalSize = cursor
	table := dtbo.Encode(header, entries)
	if uint32(len(table)) > start {
		return nil, errors.New("DTBO table overlaps the first payload")
	}
	image := make([]byte, start, cursor)
	copy(image, table)
	return append(image, body...), nil
}
