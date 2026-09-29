package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"artb/internal/avb"
	"artb/internal/buildinfo"
	"artb/internal/cpu"
	"artb/internal/executor"
	"artb/internal/fsinfo"
	"artb/internal/fsmeta"
	"artb/internal/nativebin"
	"artb/internal/workspace"

	"github.com/spf13/cobra"
)

type packOptions struct {
	output        string
	partitions    string
	jobs          int
	force         bool
	sparse        bool
	raw           bool
	noSuper       bool
	noAVB         bool
	disableVerity bool
	avbKey        string
	quiet         bool
}

type buildRequest struct {
	name         string
	tree         string
	fsConfig     string
	fileContexts string
	output       string
	filesystem   *workspace.Filesystem
	avb          *workspace.AVBFooter
	key          *rsa.PrivateKey
	entries      []fsmeta.Entry
	workers      int
	sparse       bool
}

type buildResult struct {
	size          int64
	fingerprint   string
	addedConfig   int
	addedContexts int
	elapsed       time.Duration
	filesystem    *workspace.Filesystem
	footer        *avb.FooterResult
}

const packExamples = `  artb pack rom_unpacked
  artb pack rom_unpacked -p system_a,vendor_a
  artb pack rom_unpacked -o super_new.img --sparse
  artb erofs pack rom_unpacked/system_a system_a.img
  artb ext4 pack vendor_unpacked/vendor vendor.img --size 1073741824
  artb f2fs pack system_unpacked/system system.img
  artb super pack rom_unpacked -o super.img`

func newPackCommand() *cobra.Command {
	options := packOptions{jobs: cpu.Logical()}
	cmd := &cobra.Command{
		Use:   "pack [workspace]",
		Short: "Rebuild changed partitions and super from an unpacked workspace",
		Long: `Rebuild images from a directory created by artb unpack.

A workspace is the unpack output directory holding .artb-workspace.json. Unpacking super.img, payload.bin or
a partition image records partition sizes, filesystem type, UUID, timestamps, compression, fs_config,
file_contexts and the super layout (groups, slots, sizes, alignment) there. Unpacking an EROFS, EXT4 or
F2FS image that sits inside a workspace extracts its tree into the same workspace.

artb pack compares every extracted tree and its fs_config and file_contexts with the state recorded at
unpack or the last pack, rebuilds only the partitions that changed, running them in parallel on all
logical cores, replaces their images in place, and then assembles super with lpmake when the workspace
came from a super image. New files missing from fs_config or file_contexts get their parent's owner and
SELinux context appended to those files before building.

Images that carried an AVB hashtree footer get a new dm-verity hashtree, FEC parity and footer with the
original salt and image size, and the matching descriptors in vbmeta*.img files inside the workspace are
updated. Without --avb-key their signatures then no longer match, so the device needs an unlocked
bootloader; --avb-key re-signs every workspace vbmeta image and signed footer with your RSA key and points
chain descriptors of workspace vbmeta images at it. --disable-verity also sets the verity and verification
disabled flags in those vbmeta images.`,
		Example: packExamples,
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Root().SilenceUsage = true
			root := "."
			if len(args) == 1 {
				root = args[0]
			}
			return packWorkspace(cmd.Context(), cmd, root, options)
		},
	}
	cmd.Flags().StringVarP(&options.output, "output", "o", "", "Set the super image path (default: WORKSPACE/<super source name>)")
	cmd.Flags().StringVarP(&options.partitions, "partitions", "p", "", "Only consider these comma-separated partitions for rebuilding")
	cmd.Flags().IntVarP(&options.jobs, "jobs", "j", options.jobs, "Set concurrent partition builds")
	cmd.Flags().BoolVarP(&options.force, "force", "f", false, "Rebuild selected partitions even when unchanged")
	cmd.Flags().BoolVar(&options.sparse, "sparse", false, "Write a sparse super image")
	cmd.Flags().BoolVar(&options.raw, "raw", false, "Write a raw super image even if the source was sparse")
	cmd.Flags().BoolVar(&options.noSuper, "no-super", false, "Rebuild partitions without assembling super")
	cmd.Flags().BoolVar(&options.noAVB, "no-avb", false, "Skip AVB hashtree footers and vbmeta descriptor updates")
	cmd.Flags().BoolVar(&options.disableVerity, "disable-verity", false, "Set the verity and verification disabled flags in the workspace vbmeta images")
	cmd.Flags().StringVar(&options.avbKey, "avb-key", "", "Re-sign vbmeta images and signed footers with this RSA private key (PEM)")
	cmd.Flags().BoolVarP(&options.quiet, "quiet", "q", false, "Suppress success output")
	return cmd
}

func newEROFSPackCommand() *cobra.Command {
	var fsConfig, fileContexts, compression, uuid, label, extended string
	var timestamp int64
	var pcluster, blockSize uint32
	var quiet bool
	cmd := &cobra.Command{
		Use:   "pack <tree> <image>",
		Short: "Build an EROFS image from an extracted tree",
		Long: `Build an EROFS image with mkfs.erofs. Without flags, parameters come from the workspace that owns the
tree, or fall back to lz4hc compression, the current time and a random UUID. fs_config and file_contexts
default to <tree>/../config/<name>_fs_config and <name>_file_contexts.`,
		Example: "  artb erofs pack rom_unpacked/system_a system_a.img\n  artb erofs pack system system.img -z lz4hc,9 -C 262144 -T 1230768000",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Root().SilenceUsage = true
			request, err := explicitRequest(args[0], args[1], "erofs", fsConfig, fileContexts)
			if err != nil {
				return err
			}
			params := request.filesystem
			if params.EROFS == nil {
				params.EROFS = &workspace.EROFSParams{Compression: "lz4hc"}
			}
			if cmd.Flags().Changed("compress") {
				params.EROFS.Compression = compression
			}
			if cmd.Flags().Changed("pcluster") {
				params.EROFS.PclusterSize = pcluster
			}
			if cmd.Flags().Changed("extended") {
				params.EROFS.Extended = splitPartitions(extended)
			}
			applyCommonFlags(cmd, params, uuid, label, timestamp, blockSize)
			return runExplicitBuild(cmd, request, quiet, buildEROFS)
		},
	}
	cmd.Flags().StringVar(&fsConfig, "fs-config", "", "Set the canned fs_config file")
	cmd.Flags().StringVar(&fileContexts, "file-contexts", "", "Set the file_contexts file")
	cmd.Flags().StringVarP(&compression, "compress", "z", "", "Set mkfs.erofs -z, such as lz4hc,9, lzma or none")
	cmd.Flags().Uint32VarP(&pcluster, "pcluster", "C", 0, "Set the maximum physical cluster size in bytes")
	cmd.Flags().StringVarP(&extended, "extended", "E", "", "Set comma-separated mkfs.erofs -E options")
	cmd.Flags().StringVarP(&uuid, "uuid", "U", "", "Set the filesystem UUID")
	cmd.Flags().StringVarP(&label, "label", "L", "", "Set the volume label")
	cmd.Flags().Int64VarP(&timestamp, "timestamp", "T", 0, "Set the fixed UNIX timestamp for all files")
	cmd.Flags().Uint32VarP(&blockSize, "block-size", "b", 0, "Set the block size")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress success output")
	return cmd
}

func newEXT4PackCommand() *cobra.Command {
	var fsConfig, fileContexts, uuid, label, features string
	var timestamp int64
	var blockSize, inodes uint32
	var size uint64
	var quiet bool
	cmd := &cobra.Command{
		Use:   "pack <tree> <image>",
		Short: "Build an EXT4 image from an extracted tree",
		Long: `Build an EXT4 image with mke2fs and e2fsdroid. Without flags, parameters come from the workspace that owns
the tree. The image keeps the recorded size when the tree still fits, otherwise it grows to fit.`,
		Example: "  artb ext4 pack vendor_unpacked/vendor vendor.img\n  artb ext4 pack vendor vendor.img --size 1073741824 -L vendor",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Root().SilenceUsage = true
			request, err := explicitRequest(args[0], args[1], "ext4", fsConfig, fileContexts)
			if err != nil {
				return err
			}
			params := request.filesystem
			if params.EXT4 == nil {
				params.EXT4 = &workspace.EXT4Params{InodeSize: 256, Features: []string{"has_journal", "ext_attr", "resize_inode", "dir_index", "filetype", "extent", "sparse_super", "large_file", "huge_file", "uninit_bg", "dir_nlink", "extra_isize"}}
			}
			if cmd.Flags().Changed("size") {
				bs := uint64(params.BlockSize)
				if bs == 0 {
					bs = 4096
				}
				params.EXT4.BlockCount = size / bs
			}
			if cmd.Flags().Changed("inodes") {
				params.EXT4.InodeCount = inodes
			}
			if cmd.Flags().Changed("features") {
				params.EXT4.Features = splitPartitions(features)
			}
			applyCommonFlags(cmd, params, uuid, label, timestamp, blockSize)
			return runExplicitBuild(cmd, request, quiet, buildEXT4)
		},
	}
	cmd.Flags().StringVar(&fsConfig, "fs-config", "", "Set the canned fs_config file")
	cmd.Flags().StringVar(&fileContexts, "file-contexts", "", "Set the file_contexts file")
	cmd.Flags().Uint64Var(&size, "size", 0, "Set the image size in bytes (default: recorded size or tree size plus headroom)")
	cmd.Flags().Uint32Var(&inodes, "inodes", 0, "Set the inode count")
	cmd.Flags().StringVarP(&features, "features", "O", "", "Set comma-separated mke2fs features")
	cmd.Flags().StringVarP(&uuid, "uuid", "U", "", "Set the filesystem UUID")
	cmd.Flags().StringVarP(&label, "label", "L", "", "Set the volume label")
	cmd.Flags().Int64VarP(&timestamp, "timestamp", "T", 0, "Set the fixed UNIX timestamp for all files")
	cmd.Flags().Uint32VarP(&blockSize, "block-size", "b", 0, "Set the block size")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress success output")
	return cmd
}

func newF2FSPackCommand() *cobra.Command {
	var fsConfig, fileContexts, uuid, label, features string
	var timestamp int64
	var blockSize uint32
	var size uint64
	var quiet bool
	cmd := &cobra.Command{
		Use:   "pack <tree> <image>",
		Short: "Build an F2FS image from an extracted tree",
		Long: `Build an F2FS image with mkfs.f2fs and sload.f2fs. Without flags, parameters come from the workspace that owns
the tree. The image keeps the recorded size when the tree still fits, otherwise it grows to fit. The root owner
comes from the "/" line of fs_config, and identical inputs produce identical images on every host.`,
		Example: "  artb f2fs pack system_unpacked/system system.img\n  artb f2fs pack system system.img --size 2147483648 -L system",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Root().SilenceUsage = true
			request, err := explicitRequest(args[0], args[1], "f2fs", fsConfig, fileContexts)
			if err != nil {
				return err
			}
			params := request.filesystem
			if params.F2FS == nil {
				// make_f2fs -g android features plus inode and superblock checksums.
				params.F2FS = &workspace.F2FSParams{Features: []string{"encrypt", "extra_attr", "project_quota", "inode_checksum", "quota", "verity", "sb_checksum"}}
			}
			if cmd.Flags().Changed("features") {
				params.F2FS.Features = splitPartitions(features)
			}
			applyCommonFlags(cmd, params, uuid, label, timestamp, blockSize)
			if cmd.Flags().Changed("size") {
				bs := uint64(params.BlockSize)
				if bs != 4096 && bs != 16384 {
					return fmt.Errorf("F2FS block size must be 4096 or 16384, got %d", bs)
				}
				params.F2FS.BlockCount = size / bs
				if size%bs != 0 {
					params.F2FS.BlockCount++
				}
			}
			return runExplicitBuild(cmd, request, quiet, buildF2FS)
		},
	}
	cmd.Flags().StringVar(&fsConfig, "fs-config", "", "Set the canned fs_config file")
	cmd.Flags().StringVar(&fileContexts, "file-contexts", "", "Set the file_contexts file")
	cmd.Flags().Uint64Var(&size, "size", 0, "Set the image size in bytes (default: recorded size or tree size plus headroom)")
	cmd.Flags().StringVarP(&features, "features", "O", "", "Set comma-separated mkfs.f2fs features")
	cmd.Flags().StringVarP(&uuid, "uuid", "U", "", "Set the filesystem UUID")
	cmd.Flags().StringVarP(&label, "label", "L", "", "Set the volume label")
	cmd.Flags().Int64VarP(&timestamp, "timestamp", "T", 0, "Set the fixed UNIX timestamp for all files")
	cmd.Flags().Uint32VarP(&blockSize, "block-size", "b", 0, "Set the block size (4096 or 16384)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress success output")
	return cmd
}

func newSuperPackCommand() *cobra.Command {
	var output string
	var sparse, raw, quiet bool
	cmd := &cobra.Command{
		Use:     "pack <workspace>",
		Short:   "Assemble super.img from the workspace partition images with lpmake",
		Long:    "Assemble super.img from the images in a workspace unpacked from a super image, reusing the recorded metadata size, slots, block device size, alignment, groups and partition attributes.",
		Example: "  artb super pack rom_unpacked\n  artb super pack rom_unpacked -o super.img --sparse",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Root().SilenceUsage = true
			started := time.Now()
			root, err := filepath.Abs(args[0])
			if err != nil {
				return fmt.Errorf("resolve workspace %q: %w", args[0], err)
			}
			current, err := workspace.Load(root)
			if err != nil {
				return err
			}
			path, err := assembleSuper(cmd.Context(), cmd, root, current, output, sparse, raw)
			if err != nil || quiet {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\nelapsed %.3fs\n", path, time.Since(started).Seconds())
			return err
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "Set the super image path (default: WORKSPACE/<super source name>)")
	cmd.Flags().BoolVar(&sparse, "sparse", false, "Write a sparse super image")
	cmd.Flags().BoolVar(&raw, "raw", false, "Write a raw super image even if the source was sparse")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress success output")
	return cmd
}

func applyCommonFlags(cmd *cobra.Command, params *workspace.Filesystem, uuid, label string, timestamp int64, blockSize uint32) {
	if cmd.Flags().Changed("uuid") {
		params.UUID = uuid
	}
	if cmd.Flags().Changed("label") {
		params.Label = label
	}
	if cmd.Flags().Changed("timestamp") {
		params.Timestamp = timestamp
	}
	if cmd.Flags().Changed("block-size") {
		params.BlockSize = blockSize
	}
}

// explicitRequest starts from the owning workspace record when there is one, so a single rebuild keeps the original parameters.
func explicitRequest(tree, image, kind, fsConfig, fileContexts string) (buildRequest, error) {
	treePath, err := filepath.Abs(tree)
	if err != nil {
		return buildRequest{}, fmt.Errorf("resolve tree %q: %w", tree, err)
	}
	imagePath, err := filepath.Abs(image)
	if err != nil {
		return buildRequest{}, fmt.Errorf("resolve image %q: %w", image, err)
	}
	name := filepath.Base(treePath)
	root := filepath.Dir(treePath)
	request := buildRequest{name: name, tree: treePath, output: imagePath, workers: cpu.Logical(), filesystem: &workspace.Filesystem{Type: kind, BlockSize: 4096, Timestamp: time.Now().Unix()}}
	if workspace.Exists(root) {
		current, err := workspace.Load(root)
		if err != nil {
			return request, err
		}
		for _, partition := range current.Partitions {
			if recorded := partition.Filesystem; recorded != nil && workspace.Path(root, recorded.Tree) == treePath {
				if recorded.Type != kind {
					return request, fmt.Errorf("%q was unpacked from an %s image", treePath, recorded.Type)
				}
				copied := *recorded
				request.filesystem, request.avb = &copied, recorded.AVB
				request.fsConfig = workspace.Path(root, recorded.FSConfig)
				request.fileContexts = workspace.Path(root, recorded.FileContexts)
			}
		}
	}
	if fsConfig != "" {
		request.fsConfig = fsConfig
	} else if request.fsConfig == "" {
		request.fsConfig = filepath.Join(root, "config", name+"_fs_config")
	}
	if fileContexts != "" {
		request.fileContexts = fileContexts
	} else if request.fileContexts == "" {
		request.fileContexts = filepath.Join(root, "config", name+"_file_contexts")
	}
	return request, nil
}

func runExplicitBuild(cmd *cobra.Command, request buildRequest, quiet bool, build func(context.Context, buildRequest) (buildResult, error)) error {
	if request.filesystem.UUID == "" {
		uuid, err := randomUUID()
		if err != nil {
			return err
		}
		request.filesystem.UUID = uuid
	}
	result, err := build(cmd.Context(), request)
	if err != nil {
		return err
	}
	if err = reportAdded(cmd, request.name, result); err != nil || quiet {
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\nelapsed %.3fs\n", request.output, result.elapsed.Seconds())
	return err
}

func reportAdded(cmd *cobra.Command, name string, result buildResult) error {
	if result.addedConfig == 0 && result.addedContexts == 0 {
		return nil
	}
	_, err := fmt.Fprintf(cmd.ErrOrStderr(), "%s: appended %d fs_config and %d file_contexts entries for new paths\n", name, result.addedConfig, result.addedContexts)
	return err
}

func packWorkspace(ctx context.Context, cmd *cobra.Command, root string, options packOptions) error {
	started := time.Now()
	if options.jobs < 1 {
		return fmt.Errorf("jobs must be greater than zero")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve workspace %q: %w", root, err)
	}
	current, err := workspace.Load(root)
	if err != nil {
		return err
	}
	selected := map[string]bool{}
	for _, name := range splitPartitions(options.partitions) {
		if _, ok := current.Partitions[name]; !ok {
			return fmt.Errorf("partition %q is not in workspace %q", name, root)
		}
		selected[name] = true
	}
	var candidates, trees []string
	for _, name := range current.Names() {
		if len(selected) > 0 && !selected[name] {
			continue
		}
		if current.Partitions[name].Filesystem != nil {
			candidates = append(candidates, name)
		} else if current.Partitions[name].DeviceTree != nil {
			trees = append(trees, name)
		}
	}
	vbmetas, err := vbmetaImages(root, current)
	if err != nil {
		return err
	}
	if options.disableVerity && len(vbmetas) == 0 {
		return fmt.Errorf("--disable-verity: workspace %q holds no vbmeta*.img; copy vbmeta.img there first", root)
	}
	var key *rsa.PrivateKey
	if options.avbKey != "" {
		if key, err = avb.LoadKey(options.avbKey); err != nil {
			return err
		}
	}
	requests, unchanged, err := planBuilds(root, current, candidates, options.force, options.noAVB)
	if err != nil {
		return err
	}
	for index := range requests {
		requests[index].key = key
	}
	results, err := runBuilds(ctx, root, requests, options.jobs)
	if err != nil {
		return err
	}
	treeResults, treeUnchanged, err := packDeviceTrees(ctx, root, current, trees, options.force, options.noAVB, key)
	if err != nil {
		return err
	}
	unchanged = append(unchanged, treeUnchanged...)
	footers := map[string]*avb.FooterResult{}
	for _, request := range requests {
		if footer := results[request.name].footer; footer != nil {
			footers[request.name] = footer
		}
	}
	for name, result := range treeResults {
		if result.footer != nil {
			footers[name] = result.footer
		}
	}
	notes, warnings, err := updateVBMeta(root, vbmetas, footers, options.disableVerity, key)
	if err != nil {
		return err
	}
	var superPath string
	if current.Super != nil && !options.noSuper {
		// Reload so the assembler sees the sizes the builds just recorded.
		if current, err = workspace.Load(root); err != nil {
			return err
		}
		if superPath, err = assembleSuper(ctx, cmd, root, current, options.output, options.sparse, options.raw); err != nil {
			return err
		}
	}
	for _, request := range requests {
		if err = reportAdded(cmd, request.name, results[request.name]); err != nil {
			return err
		}
	}
	for _, warning := range warnings {
		if _, err = fmt.Fprintln(cmd.ErrOrStderr(), warning); err != nil {
			return err
		}
	}
	if options.quiet {
		return nil
	}
	var out strings.Builder
	for _, request := range requests {
		fmt.Fprintf(&out, "%s rebuilt %.3fs\n", request.name, results[request.name].elapsed.Seconds())
	}
	for _, name := range slices.Sorted(maps.Keys(treeResults)) {
		fmt.Fprintf(&out, "%s rebuilt %.3fs (compiled %d of %d)\n", name, treeResults[name].elapsed.Seconds(), treeResults[name].compiled, treeResults[name].trees)
	}
	for _, name := range unchanged {
		fmt.Fprintf(&out, "%s unchanged\n", name)
	}
	for _, note := range notes {
		fmt.Fprintln(&out, note)
	}
	if superPath != "" {
		fmt.Fprintf(&out, "super %s\n", superPath)
	}
	fmt.Fprintf(&out, "elapsed %.3fs\n", time.Since(started).Seconds())
	_, err = fmt.Fprint(cmd.OutOrStdout(), out.String())
	return err
}

// planBuilds fingerprints every candidate tree in parallel and keeps the ones that changed since the recorded state.
func planBuilds(root string, current *workspace.Workspace, candidates []string, force, noAVB bool) ([]buildRequest, []string, error) {
	requests := make([]*buildRequest, len(candidates))
	errs := make([]error, len(candidates))
	var group sync.WaitGroup
	slots := make(chan struct{}, cpu.Logical())
	for index, name := range candidates {
		group.Add(1)
		go func(index int, name string) {
			defer group.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			partition := current.Partitions[name]
			recorded := partition.Filesystem
			request := buildRequest{name: name, tree: workspace.Path(root, recorded.Tree), fsConfig: workspace.Path(root, recorded.FSConfig), fileContexts: workspace.Path(root, recorded.FileContexts), output: workspace.Path(root, partition.Image), filesystem: recorded, sparse: partition.Sparse}
			entries, err := fsmeta.Scan(request.tree)
			if err != nil {
				errs[index] = err
				return
			}
			fingerprint, err := fsmeta.Fingerprint(entries, request.fsConfig, request.fileContexts)
			if err != nil {
				errs[index] = err
				return
			}
			info, statErr := os.Stat(request.output)
			if force || fingerprint != recorded.Fingerprint || statErr != nil {
				request.entries = entries
				// Workspaces unpacked before the footer was recorded still find it on the image about to be replaced.
				if request.avb = recorded.AVB; !noAVB && request.avb == nil && statErr == nil {
					request.avb = hashtreeFooter(request.output, info.Size())
				}
				if noAVB {
					request.avb = nil
				}
				requests[index] = &request
			}
		}(index, name)
	}
	group.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, nil, err
	}
	var planned []buildRequest
	var unchanged []string
	for index, request := range requests {
		if request == nil {
			unchanged = append(unchanged, candidates[index])
		} else {
			planned = append(planned, *request)
		}
	}
	return planned, unchanged, nil
}

// runBuilds rebuilds partitions concurrently and splits mkfs.erofs workers so the total stays near the logical core count.
func runBuilds(ctx context.Context, root string, requests []buildRequest, jobs int) (map[string]buildResult, error) {
	results := map[string]buildResult{}
	if len(requests) == 0 {
		return results, nil
	}
	concurrent := min(jobs, len(requests))
	workers := max(1, cpu.Logical()/concurrent)
	var mutex sync.Mutex
	var group sync.WaitGroup
	errs := make([]error, len(requests))
	slots := make(chan struct{}, concurrent)
	for index := range requests {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			request := requests[index]
			request.workers = workers
			build := buildEROFS
			switch request.filesystem.Type {
			case "ext4":
				build = buildEXT4
			case "f2fs":
				build = buildF2FS
			}
			result, err := build(ctx, request)
			if err != nil {
				errs[index] = fmt.Errorf("pack %s: %w", request.name, err)
				return
			}
			err = workspace.Update(ctx, root, func(current *workspace.Workspace) error {
				partition := current.Partitions[request.name]
				if partition == nil || partition.Filesystem == nil {
					return fmt.Errorf("partition %q vanished from workspace", request.name)
				}
				partition.Size = result.size
				partition.Filesystem.Fingerprint = result.fingerprint
				merged := mergeBuildParams(*partition.Filesystem, result.filesystem)
				if merged.AVB == nil {
					merged.AVB = request.avb
				}
				*partition.Filesystem = merged
				return nil
			})
			if err != nil {
				errs[index] = err
				return
			}
			mutex.Lock()
			results[request.name] = result
			mutex.Unlock()
		}(index)
	}
	group.Wait()
	return results, errors.Join(errs...)
}

// mergeBuildParams keeps parameters the build had to change, such as an EXT4 image grown to fit.
func mergeBuildParams(recorded workspace.Filesystem, used *workspace.Filesystem) workspace.Filesystem {
	if used.EXT4 != nil && recorded.EXT4 != nil {
		ext4 := *recorded.EXT4
		ext4.BlockCount, ext4.InodeCount = used.EXT4.BlockCount, used.EXT4.InodeCount
		recorded.EXT4 = &ext4
	}
	if used.F2FS != nil && recorded.F2FS != nil {
		f2fs := *recorded.F2FS
		f2fs.BlockCount = used.F2FS.BlockCount
		recorded.F2FS = &f2fs
	}
	return recorded
}

// prepareConfigs completes fs_config and resolves file_contexts into an exact list written next to the build output.
func prepareConfigs(request *buildRequest, directory string, extra ...fsmeta.Entry) (string, int, int, error) {
	if request.entries == nil {
		entries, err := fsmeta.Scan(request.tree)
		if err != nil {
			return "", 0, 0, err
		}
		request.entries = entries
	}
	addedConfig, err := fsmeta.CompleteFSConfig(request.fsConfig, request.entries)
	if err != nil {
		return "", 0, 0, err
	}
	resolved, addedContexts, err := fsmeta.ResolveContexts(request.fileContexts, request.entries, extra...)
	if err != nil {
		return "", 0, 0, err
	}
	path := filepath.Join(directory, request.name+"_file_contexts")
	if err = os.WriteFile(path, []byte(resolved), 0o644); err != nil {
		return "", 0, 0, fmt.Errorf("write resolved file_contexts: %w", err)
	}
	return path, addedConfig, addedContexts, nil
}

// finishBuild moves the new image into place and fingerprints the tree with the configs as they now stand.
func finishBuild(ctx context.Context, request buildRequest, temporary string, started time.Time, addedConfig, addedContexts int) (buildResult, error) {
	var footer *avb.FooterResult
	if request.avb != nil {
		var err error
		if footer, err = avb.AddHashtreeFooter(temporary, request.avb.VBMeta, request.avb.Size, request.key, max(1, request.workers)); err != nil {
			return buildResult{}, fmt.Errorf("add AVB hashtree footer: %w", err)
		}
	}
	if request.sparse {
		sparse := temporary + ".sparse"
		if err := runTool(ctx, "img2simg", nil, "", temporary, sparse); err != nil {
			return buildResult{}, err
		}
		temporary = sparse
	}
	if err := os.MkdirAll(filepath.Dir(request.output), 0o755); err != nil {
		return buildResult{}, fmt.Errorf("create output directory: %w", err)
	}
	if err := moveFile(temporary, request.output); err != nil {
		return buildResult{}, err
	}
	info, err := os.Stat(request.output)
	if err != nil {
		return buildResult{}, fmt.Errorf("stat %q: %w", request.output, err)
	}
	fingerprint, err := fsmeta.Fingerprint(request.entries, request.fsConfig, request.fileContexts)
	if err != nil {
		return buildResult{}, err
	}
	return buildResult{size: info.Size(), fingerprint: fingerprint, addedConfig: addedConfig, addedContexts: addedContexts, elapsed: time.Since(started), filesystem: request.filesystem, footer: footer}, nil
}

// vbmetaImages lists the vbmeta images inside the workspace: registered vbmeta partitions and loose vbmeta*.img files.
func vbmetaImages(root string, current *workspace.Workspace) ([]string, error) {
	seen := map[string]bool{}
	var images []string
	add := func(path string) {
		if relative := workspace.Relative(root, path); filepath.IsAbs(relative) || seen[relative] {
			return
		}
		head := make([]byte, 4)
		file, err := os.Open(path)
		if err != nil {
			return
		}
		_, err = io.ReadFull(file, head)
		file.Close()
		if err == nil && string(head) == "AVB0" {
			seen[workspace.Relative(root, path)] = true
			images = append(images, path)
		}
	}
	for _, name := range current.Names() {
		if strings.HasPrefix(name, "vbmeta") {
			add(workspace.Path(root, current.Partitions[name].Image))
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("list workspace %q: %w", root, err)
	}
	for _, entry := range entries {
		if name := entry.Name(); entry.Type().IsRegular() && strings.HasPrefix(name, "vbmeta") && strings.HasSuffix(name, ".img") {
			add(filepath.Join(root, name))
		}
	}
	sort.Strings(images)
	return images, nil
}

// updateVBMeta moves rebuilt hashtree descriptors into the workspace vbmeta images, optionally disables verification
// and re-signs every workspace vbmeta image when a key is given.
func updateVBMeta(root string, images []string, footers map[string]*avb.FooterResult, disable bool, key *rsa.PrivateKey) ([]string, []string, error) {
	replacements, owners := map[string][]byte{}, map[string]string{}
	var notes, warnings []string
	for name, footer := range footers {
		replacements[footer.Partition], owners[footer.Partition] = footer.Descriptor, name
		if footer.StaleSignature {
			warnings = append(warnings, fmt.Sprintf("%s: the footer vbmeta signature no longer matches; pass --avb-key to re-sign it", name))
		}
	}
	// Chained vbmeta images re-signed here must be trusted by the images that chain to them.
	chains := map[string][]byte{}
	if key != nil {
		publicKey := avb.PublicKeyBlob(&key.PublicKey)
		for _, image := range images {
			name := strings.TrimSuffix(filepath.Base(image), ".img")
			chains[name], chains[strings.TrimSuffix(strings.TrimSuffix(name, "_a"), "_b")] = publicKey, publicKey
		}
	}
	placed := map[string]bool{}
	for _, image := range images {
		name := workspace.Relative(root, image)
		if disable {
			before, after, err := avb.SetFlags(image, "", avb.FlagHashtreeDisabled|avb.FlagVerificationDisabled, 0)
			if err != nil {
				return nil, nil, err
			}
			if before != after {
				notes = append(notes, fmt.Sprintf("%s flags 0x%x -> 0x%x", name, before, after))
			}
		}
		if len(replacements) > 0 {
			replaced, err := avb.ReplaceDescriptors(image, replacements)
			if err != nil {
				return nil, nil, err
			}
			for _, partition := range replaced.Matched {
				placed[partition] = true
			}
			if len(replaced.Updated) > 0 {
				notes = append(notes, fmt.Sprintf("%s updated %s", name, strings.Join(replaced.Updated, ",")))
			}
			if replaced.StaleSignature && key == nil {
				warnings = append(warnings, fmt.Sprintf("%s: the signature no longer matches the updated descriptors; flash it on an unlocked bootloader or pass --avb-key", name))
			}
		}
		if key != nil {
			if err := avb.SignFile(image, "", key, chains); err != nil {
				return nil, nil, err
			}
			meta, err := avb.Read(image)
			if err != nil {
				return nil, nil, err
			}
			notes = append(notes, fmt.Sprintf("%s signed %s key %s", name, meta.Algorithm, meta.PublicKeySHA1))
		}
	}
	for partition, owner := range owners {
		if !placed[partition] {
			warnings = append(warnings, fmt.Sprintf("%s: no vbmeta image in the workspace carries the %s descriptor; copy vbmeta.img into the workspace or flash with verity disabled", owner, partition))
		}
	}
	sort.Strings(warnings)
	return notes, warnings, nil
}

func buildDirectory(output string) (string, func(), error) {
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return "", nil, fmt.Errorf("create output directory: %w", err)
	}
	directory, err := os.MkdirTemp(filepath.Dir(output), ".artb-build-")
	if err != nil {
		return "", nil, fmt.Errorf("create build directory: %w", err)
	}
	return directory, func() { _ = os.RemoveAll(directory) }, nil
}

func buildEROFS(ctx context.Context, request buildRequest) (buildResult, error) {
	started := time.Now()
	directory, cleanup, err := buildDirectory(request.output)
	if err != nil {
		return buildResult{}, err
	}
	defer cleanup()
	contexts, addedConfig, addedContexts, err := prepareConfigs(&request, directory)
	if err != nil {
		return buildResult{}, err
	}
	params, filesystem := request.filesystem.EROFS, request.filesystem
	if params == nil {
		params = &workspace.EROFSParams{Compression: "lz4hc"}
	}
	var args []string
	if params.Compression != "" && params.Compression != "none" {
		args = append(args, "-z"+params.Compression)
	}
	if params.PclusterSize > 0 {
		args = append(args, "-C", strconv.FormatUint(uint64(params.PclusterSize), 10))
	}
	for _, option := range params.Extended {
		args = append(args, "-E", option)
	}
	args = append(args, "-T", strconv.FormatInt(filesystem.Timestamp, 10), "-U", filesystem.UUID)
	if filesystem.Label != "" {
		args = append(args, "-L", filesystem.Label)
	}
	// Always explicit: mkfs.erofs otherwise defaults to the host page size, which is 16 KiB on some phones.
	if filesystem.BlockSize != 0 {
		args = append(args, "-b", strconv.FormatUint(uint64(filesystem.BlockSize), 10))
	}
	temporary := filepath.Join(directory, request.name+".img")
	args = append(args, "--fs-config-file="+request.fsConfig, "--file-contexts="+contexts, "--workers="+strconv.Itoa(max(1, request.workers)), temporary, request.tree)
	if err = runTool(ctx, "mkfs.erofs", nil, "", args...); err != nil {
		return buildResult{}, err
	}
	return finishBuild(ctx, request, temporary, started, addedConfig, addedContexts)
}

// ext4Estimate sizes blocks and inodes for the tree with headroom; exact accounting is left to a retry on ENOSPC.
func ext4Estimate(entries []fsmeta.Entry, blockSize uint64, inodeSize uint64) (uint64, uint64) {
	var data uint64
	for _, entry := range entries {
		switch entry.Kind {
		case fsmeta.File:
			data += (uint64(entry.Size) + blockSize - 1) / blockSize
		case fsmeta.Dir:
			data++
		case fsmeta.Symlink:
			if len(entry.Target) >= 60 {
				data++
			}
		}
	}
	inodes := uint64(len(entries))*5/4 + 64
	tables := inodes * inodeSize / blockSize
	blocks := data + data/20 + tables + 256
	// Journal and group metadata scale with the filesystem, so reserve a fixed fraction on top.
	blocks += blocks / 16
	return blocks, inodes
}

func buildEXT4(ctx context.Context, request buildRequest) (buildResult, error) {
	started := time.Now()
	directory, cleanup, err := buildDirectory(request.output)
	if err != nil {
		return buildResult{}, err
	}
	defer cleanup()
	contexts, addedConfig, addedContexts, err := prepareConfigs(&request, directory, fsmeta.Entry{Path: "/lost+found", Kind: fsmeta.Dir})
	if err != nil {
		return buildResult{}, err
	}
	filesystem := *request.filesystem
	params := *filesystem.EXT4
	filesystem.EXT4 = &params
	request.filesystem = &filesystem
	blockSize := uint64(filesystem.BlockSize)
	if blockSize == 0 {
		blockSize = 4096
		filesystem.BlockSize = 4096
	}
	if params.InodeSize == 0 {
		params.InodeSize = 256
	}
	blocks, inodes := ext4Estimate(request.entries, blockSize, uint64(params.InodeSize))
	if params.BlockCount < blocks {
		params.BlockCount = blocks
	}
	if uint64(params.InodeCount) < inodes {
		params.InodeCount = uint32(inodes)
	}
	// e2fsprogs treats a zero fake time as unset, so an epoch-built image falls back to one second.
	fakeTime := max(params.CreatedAt, 1)
	environment := []string{"E2FSPROGS_FAKE_TIME=" + strconv.FormatInt(fakeTime, 10)}
	temporary := filepath.Join(directory, request.name+".img")
	for attempt := 0; ; attempt++ {
		if err = os.Remove(temporary); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return buildResult{}, fmt.Errorf("remove %q: %w", temporary, err)
		}
		args := []string{"-q", "-F", "-t", "ext4", "-b", strconv.FormatUint(blockSize, 10), "-I", strconv.FormatUint(uint64(params.InodeSize), 10), "-N", strconv.FormatUint(uint64(params.InodeCount), 10)}
		if params.BlockCount > 0 && params.ReservedBlocks > 0 {
			args = append(args, "-m", strconv.FormatFloat(float64(params.ReservedBlocks)*100/float64(params.BlockCount), 'f', -1, 64))
		} else {
			args = append(args, "-m", "0")
		}
		if filesystem.Label != "" {
			args = append(args, "-L", filesystem.Label)
		}
		if params.LastMounted != "" {
			args = append(args, "-M", params.LastMounted)
		}
		args = append(args, "-U", filesystem.UUID)
		// mke2fs keeps only the last -E, so every extended option goes into one list.
		var extended []string
		if params.HashSeed != "" {
			extended = append(extended, "hash_seed="+params.HashSeed)
		}
		if params.HashSignedness != "" {
			extended = append(extended, "hash_signedness="+params.HashSignedness)
		}
		if len(extended) > 0 {
			args = append(args, "-E", strings.Join(extended, ","))
		}
		if params.FlexBGSize > 0 {
			args = append(args, "-G", strconv.FormatUint(uint64(params.FlexBGSize), 10))
		}
		if params.BlocksPerGroup > 0 && params.BlocksPerGroup != uint32(blockSize*8) {
			args = append(args, "-g", strconv.FormatUint(uint64(params.BlocksPerGroup), 10))
		}
		args = append(args, "-O", fsinfo.MkfsFeatures(params), temporary, strconv.FormatUint(params.BlockCount, 10))
		if err = runTool(ctx, "mke2fs", environment, "", args...); err != nil {
			return buildResult{}, err
		}
		droid := []string{"-e", "-T", strconv.FormatInt(filesystem.Timestamp, 10), "-C", request.fsConfig, "-S", contexts, "-a", "/", "-f", request.tree}
		if params.SharedBlocks {
			droid = append(droid, "-s")
		}
		err = runTool(ctx, "e2fsdroid", environment, "", append(droid, temporary)...)
		if err == nil {
			break
		}
		if attempt >= 3 || !strings.Contains(strings.ToLower(err.Error()), "space") {
			return buildResult{}, err
		}
		params.BlockCount += params.BlockCount / 4
		params.InodeCount += params.InodeCount / 4
	}
	return finishBuild(ctx, request, temporary, started, addedConfig, addedContexts)
}

// f2fsMinimumBytes is the smallest volume mkfs.f2fs formats with default segment sizes; smaller files make it fail or crash.
const f2fsMinimumBytes = 48 << 20

// f2fsEstimate sizes a volume for the tree: data and node blocks plus a fifth for overprovisioning and segment waste, and a fixed metadata allowance.
func f2fsEstimate(entries []fsmeta.Entry, blockSize uint64) uint64 {
	perNode := (blockSize - 24) / 4
	minimumBytes := uint64(f2fsMinimumBytes)
	if blockSize == 16384 {
		minimumBytes = 256 << 20
	}
	var blocks uint64
	for _, entry := range entries {
		blocks++
		switch entry.Kind {
		case fsmeta.File:
			data := (uint64(entry.Size) + blockSize - 1) / blockSize
			blocks += data + data/perNode
		case fsmeta.Dir:
			blocks += 2
		case fsmeta.Symlink:
			blocks++
		}
	}
	return max(blocks+blocks/5+(32<<20)/blockSize, minimumBytes/blockSize)
}

// f2fsFull reports sload running out of free blocks, which a larger volume fixes.
func f2fsFull(err error) bool {
	text := err.Error()
	return strings.Contains(text, "Can't find free block") || strings.Contains(text, "Not enough space") || strings.Contains(text, "No space")
}

func buildF2FS(ctx context.Context, request buildRequest) (buildResult, error) {
	started := time.Now()
	if request.filesystem == nil || request.filesystem.F2FS == nil {
		return buildResult{}, errors.New("F2FS build parameters are missing")
	}
	if request.filesystem.BlockSize != 4096 && request.filesystem.BlockSize != 16384 {
		return buildResult{}, fmt.Errorf("F2FS block size must be 4096 or 16384, got %d", request.filesystem.BlockSize)
	}
	directory, cleanup, err := buildDirectory(request.output)
	if err != nil {
		return buildResult{}, err
	}
	defer cleanup()
	contexts, addedConfig, addedContexts, err := prepareConfigs(&request, directory)
	if err != nil {
		return buildResult{}, err
	}
	filesystem := *request.filesystem
	params := *filesystem.F2FS
	filesystem.F2FS = &params
	request.filesystem = &filesystem
	blockSize := uint64(filesystem.BlockSize)
	params.BlockCount = max(params.BlockCount, f2fsEstimate(request.entries, blockSize))
	// sload never applies fs_config to the root, so its owner goes to mkfs.
	uid, gid, err := fsmeta.RootOwner(request.fsConfig)
	if err != nil {
		return buildResult{}, err
	}
	// The patched tools write this instead of the build host's kernel release into the superblock.
	environment := []string{"ARTB_F2FS_VERSION=" + params.Version}
	if strings.HasSuffix(request.fsConfig, "_fs_config") {
		hardlinks := strings.TrimSuffix(request.fsConfig, "_fs_config") + "_hardlinks"
		filtered, filterErr := filterF2FSHardlinks(request.tree, hardlinks, directory)
		if filterErr != nil {
			return buildResult{}, filterErr
		}
		if filtered != "" {
			environment = append(environment, "ARTB_F2FS_HARDLINKS="+filtered)
		}
	}
	timestamp := strconv.FormatInt(filesystem.Timestamp, 10)
	temporary := filepath.Join(directory, request.name+".img")
	for attempt := 0; ; attempt++ {
		if params.BlockCount > math.MaxInt64/blockSize {
			return buildResult{}, fmt.Errorf("F2FS image size exceeds maximum file size: %d blocks of %d bytes", params.BlockCount, blockSize)
		}
		if err = createSized(temporary, int64(params.BlockCount*blockSize)); err != nil {
			return buildResult{}, err
		}
		// -r pins the checkpoint version so identical inputs give identical images.
		args := []string{"-q", "-f", "-O", strings.Join(params.Features, ","), "-U", filesystem.UUID, "-R", fmt.Sprintf("%d:%d", uid, gid), "-T", timestamp, "-r"}
		if blockSize != 4096 {
			args = append(args, "-b", strconv.FormatUint(blockSize, 10))
		}
		if filesystem.Label != "" {
			args = append(args, "-l", filesystem.Label)
		}
		if params.SegmentsPerSection > 1 {
			args = append(args, "-s", strconv.FormatUint(uint64(params.SegmentsPerSection), 10))
		}
		if params.SectionsPerZone > 1 {
			args = append(args, "-z", strconv.FormatUint(uint64(params.SectionsPerZone), 10))
		}
		if params.Encoding != "" {
			args = append(args, "-C", params.Encoding)
		}
		if err = runTool(ctx, "mkfs.f2fs", environment, "", append(args, temporary)...); err != nil {
			return buildResult{}, err
		}
		err = runTool(ctx, "sload.f2fs", environment, "", "-f", request.tree, "-C", request.fsConfig, "-s", contexts, "-t", "/", "-T", timestamp, temporary)
		if err == nil {
			break
		}
		if attempt >= 3 || !f2fsFull(err) {
			return buildResult{}, err
		}
		params.BlockCount += params.BlockCount / 4
	}
	return finishBuild(ctx, request, temporary, started, addedConfig, addedContexts)
}

func filterF2FSHardlinks(tree, source, directory string) (string, error) {
	data, err := os.ReadFile(source)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read F2FS hardlinks %q: %w", source, err)
	}
	if len(data) == 0 {
		return "", nil
	}
	parts := bytes.Split(data, []byte{0})
	if len(parts)%2 != 1 || len(parts[len(parts)-1]) != 0 {
		return "", fmt.Errorf("invalid F2FS hardlinks file %q", source)
	}
	var retained bytes.Buffer
	for index := 0; index < len(parts)-1; index += 2 {
		paths := [2]string{}
		infos := [2]os.FileInfo{}
		valid := true
		for member := range paths {
			name := string(parts[index+member])
			if !strings.HasPrefix(name, "/") || name == "/" || filepath.Clean(filepath.FromSlash(name)) != filepath.FromSlash(name) {
				return "", fmt.Errorf("invalid F2FS hardlink path %q", name)
			}
			paths[member] = filepath.Join(tree, filepath.FromSlash(strings.TrimPrefix(name, "/")))
			infos[member], err = os.Lstat(paths[member])
			if errors.Is(err, fs.ErrNotExist) {
				valid = false
				break
			}
			if err != nil {
				return "", fmt.Errorf("stat F2FS hardlink %q: %w", paths[member], err)
			}
			if !infos[member].Mode().IsRegular() {
				valid = false
				break
			}
		}
		if !valid || infos[0].Size() != infos[1].Size() {
			continue
		}
		if !os.SameFile(infos[0], infos[1]) {
			first, firstErr := digestF2FSFile(paths[0])
			second, secondErr := digestF2FSFile(paths[1])
			if firstErr != nil || secondErr != nil {
				return "", errors.Join(firstErr, secondErr)
			}
			if first != second {
				continue
			}
		}
		retained.Write(parts[index])
		retained.WriteByte(0)
		retained.Write(parts[index+1])
		retained.WriteByte(0)
	}
	if retained.Len() == 0 {
		return "", nil
	}
	path := filepath.Join(directory, "hardlinks")
	if err = os.WriteFile(path, retained.Bytes(), 0o600); err != nil {
		return "", fmt.Errorf("write F2FS hardlinks %q: %w", path, err)
	}
	return path, nil
}

func digestF2FSFile(path string) ([sha256.Size]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("open %q: %w", path, err)
	}
	digest := sha256.New()
	_, copyErr := io.Copy(digest, file)
	closeErr := file.Close()
	if err = errors.Join(copyErr, closeErr); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("hash %q: %w", path, err)
	}
	return [sha256.Size]byte(digest.Sum(nil)), nil
}

// createSized makes an empty file of the given length; untouched regions stay sparse where the host filesystem allows it.
func createSized(path string, size int64) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %q: %w", path, err)
	}
	if err = file.Truncate(size); err != nil {
		file.Close()
		return fmt.Errorf("size %q: %w", path, err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("close %q: %w", path, err)
	}
	return nil
}

// assembleSuper rebuilds super with lpmake from the recorded LP metadata and the current partition images.
func assembleSuper(ctx context.Context, cmd *cobra.Command, root string, current *workspace.Workspace, output string, sparse, raw bool) (string, error) {
	if current.Super == nil {
		return "", fmt.Errorf("workspace %q was not unpacked from a super image", root)
	}
	metadata := current.Super.Metadata
	if len(metadata.BlockDevices) != 1 {
		return "", fmt.Errorf("super layouts with %d block devices are not supported", len(metadata.BlockDevices))
	}
	device := metadata.BlockDevices[0]
	if output == "" {
		output = filepath.Join(root, current.Super.Source)
	}
	output, err := filepath.Abs(output)
	if err != nil {
		return "", fmt.Errorf("resolve output %q: %w", output, err)
	}
	args := []string{"--metadata-size", strconv.FormatUint(uint64(metadata.MetadataMaxSize), 10), "--metadata-slots", strconv.FormatUint(uint64(metadata.MetadataSlotCount), 10), "--super-name", device.Name, "--block-size", strconv.FormatUint(uint64(metadata.LogicalBlockSize), 10), "--device", fmt.Sprintf("%s:%d:%d:%d", device.Name, device.Size, device.Alignment, device.AlignmentOffset)}
	if metadata.HeaderFlags&workspace.HeaderFlagVirtualAB != 0 {
		args = append(args, "--virtual-ab")
	}
	for _, group := range metadata.Groups {
		if group.Name != "default" {
			args = append(args, "--group", fmt.Sprintf("%s:%d", group.Name, group.MaximumSize))
		}
	}
	var dropped []string
	sizes := map[string]uint64{}
	for _, partition := range metadata.Partitions {
		attributes := "none"
		if partition.Attributes&workspace.PartitionAttrReadonly != 0 {
			attributes = "readonly"
		}
		if partition.Attributes&^workspace.PartitionAttrReadonly != 0 {
			dropped = append(dropped, fmt.Sprintf("%s(0x%x)", partition.Name, partition.Attributes))
		}
		var size int64
		image := ""
		if recorded := current.Partitions[partition.Name]; recorded != nil {
			image = workspace.Path(root, recorded.Image)
			info, err := os.Stat(image)
			if err != nil {
				return "", fmt.Errorf("partition %s image: %w", partition.Name, err)
			}
			size = info.Size()
			if recorded.Sparse {
				return "", fmt.Errorf("partition %s image %q is sparse; lpmake needs raw images", partition.Name, image)
			}
		} else if partition.Size != 0 {
			return "", fmt.Errorf("partition %s has no image in workspace %q", partition.Name, root)
		}
		sizes[partition.Name] = uint64(size)
		args = append(args, "--partition", fmt.Sprintf("%s:%s:%d:%s", partition.Name, attributes, size, partition.Group))
		if size > 0 {
			args = append(args, "--image", partition.Name+"="+image)
		}
	}
	if err = checkSuperCapacity(metadata, sizes); err != nil {
		return "", err
	}
	if len(dropped) > 0 {
		sort.Strings(dropped)
		if _, err = fmt.Fprintf(cmd.ErrOrStderr(), "super: lpmake keeps only the readonly attribute; dropped %s\n", strings.Join(dropped, ", ")); err != nil {
			return "", err
		}
	}
	if (current.Super.Sparse || sparse) && !raw {
		args = append(args, "--sparse")
	}
	if err = os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return "", fmt.Errorf("create output directory: %w", err)
	}
	args = append(args, "--output", output)
	if err = runTool(ctx, "lpmake", nil, "", args...); err != nil {
		return "", err
	}
	return output, nil
}

// checkSuperCapacity repeats liblp's group limits and sequential aligned allocation so an oversized rebuild names the partitions that grew.
func checkSuperCapacity(metadata workspace.Metadata, sizes map[string]uint64) error {
	device := metadata.BlockDevices[0]
	block, alignment := uint64(max(metadata.LogicalBlockSize, 512)), uint64(max(device.Alignment, 512))
	alignUp := func(value, unit uint64) uint64 { return (value + unit - 1) / unit * unit }
	human := func(value uint64) string {
		if value < 1<<20 {
			return fmt.Sprintf("%d KiB", (value+1023)>>10)
		}
		return fmt.Sprintf("%.1f MiB", float64(value)/(1<<20))
	}
	used := map[string]uint64{}
	end := device.FirstLogicalSector * 512
	var growth []string
	grew := map[string][]string{}
	for _, partition := range metadata.Partitions {
		size := alignUp(sizes[partition.Name], block)
		used[partition.Group] += size
		if size > 0 {
			end = alignUp(end, alignment) + size
		}
		if size > partition.Size {
			change := partition.Name + " +" + human(size-partition.Size)
			grew[partition.Group] = append(grew[partition.Group], change)
			growth = append(growth, change)
		}
	}
	var problems []string
	for _, group := range metadata.Groups {
		if group.MaximumSize > 0 && used[group.Name] > group.MaximumSize {
			problems = append(problems, fmt.Sprintf("group %s needs %d bytes but holds at most %d, over by %s (grown: %s)", group.Name, used[group.Name], group.MaximumSize, human(used[group.Name]-group.MaximumSize), strings.Join(grew[group.Name], ", ")))
		}
	}
	if end > device.Size {
		problems = append(problems, fmt.Sprintf("block device %s needs %d bytes but holds %d, over by %s (grown: %s)", device.Name, end, device.Size, human(end-device.Size), strings.Join(growth, ", ")))
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("super: rebuilt partitions no longer fit the recorded layout: %s", strings.Join(problems, "; "))
}

// randomUUID gives standalone builds a fresh RFC 4122 version 4 identifier.
func randomUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate uuid: %w", err)
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}

func runTool(ctx context.Context, tool string, environment []string, dir string, args ...string) error {
	executable, err := nativebin.New(buildinfo.Version).Ensure(ctx, tool)
	if err != nil {
		return err
	}
	var output bytes.Buffer
	if _, err = executor.New(1).Run(ctx, executor.Spec{Name: executable, Args: args, Dir: dir, Env: environment, Stdout: &output, Stderr: &output}); err != nil {
		return fmt.Errorf("%s: %w: %s", tool, err, outputTail(output.String(), 20))
	}
	return nil
}

// outputTail keeps the last lines of a tool's output; carriage returns count as breaks so progress spinners collapse.
func outputTail(text string, count int) string {
	var lines []string
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' }) {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines[max(0, len(lines)-count):], "\n")
}
