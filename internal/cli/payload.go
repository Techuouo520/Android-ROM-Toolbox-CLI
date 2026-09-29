package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"artb/internal/cpu"
	"artb/internal/detect"
	"artb/internal/progress"

	"github.com/spf13/cobra"
	"github.com/ssut/payload-dumper-go/payload"
)

type payloadPartitionOutput struct {
	Name        string   `json:"name"`
	Size        uint64   `json:"size"`
	SHA256      string   `json:"sha256,omitempty"`
	NeedsSource bool     `json:"needs_source"`
	Operations  int      `json:"operations"`
	Unsupported []string `json:"unsupported_operations,omitempty"`
}

type payloadListOutput struct {
	Version      uint64                   `json:"version"`
	MinorVersion uint32                   `json:"minor_version"`
	BlockSize    uint64                   `json:"block_size"`
	Delta        bool                     `json:"delta"`
	Partitions   []payloadPartitionOutput `json:"partitions"`
}

type unpackOptions struct {
	partitions string
	output     string
	old        string
	jobs       int
	noVerify   bool
	quiet      bool
	// source and sparse describe the original image when a sparse input was expanded to a temporary raw file.
	source string
	sparse bool
	// expect is set by format commands such as artb erofs unpack to reject inputs of another format.
	expect detect.Type
}

func newPayloadListCommand() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{Use: "list <payload.bin|ota.zip>", Short: "List payload partitions", Example: "  artb payload list ota.zip\n  artb payload list payload.bin --json", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Root().SilenceUsage = true
		path, err := filepath.Abs(args[0])
		if err != nil {
			return fmt.Errorf("resolve %q: %w", args[0], err)
		}
		return writePayloadList(cmd, path, jsonOutput)
	}}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Print JSON output")
	return cmd
}

func newUnpackCommand() *cobra.Command {
	options := unpackOptions{jobs: cpu.Logical()}
	cmd := &cobra.Command{Use: "unpack <file>", Short: "Detect the format and extract any supported image", Long: `Detect the input format and extract it: payload.bin or OTA zip, raw or sparse super.img, EROFS, EXT4,
sparse partition images and boot, init_boot, vendor_boot or recovery images. The output directory becomes a
workspace that artb pack can rebuild. Format-specific options, such as --old and --no-verify for delta
payloads, live under the format commands (artb payload unpack, artb super unpack, artb erofs unpack, ...).`, Example: "  artb unpack ota.zip\n  artb unpack super.img -p system_a,vendor_a\n  artb unpack super_unpacked/system_a.img", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Root().SilenceUsage = true
		return unpackDetected(cmd.Context(), cmd, args[0], options)
	}}
	cmd.Flags().StringVarP(&options.partitions, "partitions", "p", "", "Extract comma-separated partitions from a payload or super image")
	cmd.Flags().StringVarP(&options.output, "output", "o", "", "Set output directory")
	cmd.Flags().IntVarP(&options.jobs, "jobs", "j", options.jobs, "Set concurrent extraction workers")
	cmd.Flags().BoolVarP(&options.quiet, "quiet", "q", false, "Suppress success output")
	return cmd
}

func writePayloadList(cmd *cobra.Command, path string, jsonOutput bool) (err error) {
	pl, err := payload.Open(path)
	if err != nil {
		return fmt.Errorf("open payload %q: %w", path, err)
	}
	defer func() {
		if closeErr := pl.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close payload %q: %w", path, closeErr)
		}
	}()
	output := payloadListOutput{Version: pl.Header().Version, MinorVersion: pl.MinorVersion(), BlockSize: pl.BlockSize(), Delta: pl.IsDelta()}
	for _, partition := range pl.Partitions() {
		output.Partitions = append(output.Partitions, payloadPartitionOutput{Name: partition.Name, Size: partition.Size, SHA256: hex.EncodeToString(partition.Hash), NeedsSource: partition.NeedsSource, Operations: partition.TotalOperations, Unsupported: partition.UnsupportedOperations})
	}
	if jsonOutput {
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetEscapeHTML(false)
		return encoder.Encode(output)
	}
	if _, err = fmt.Fprintf(cmd.OutOrStdout(), "version %d\nminor_version %d\nblock_size %d\ndelta %t\n", output.Version, output.MinorVersion, output.BlockSize, output.Delta); err != nil {
		return err
	}
	for _, partition := range output.Partitions {
		if _, err = fmt.Fprintf(cmd.OutOrStdout(), "%s %d %d %t\n", partition.Name, partition.Size, partition.Operations, partition.NeedsSource); err != nil {
			return err
		}
	}
	return nil
}

func unpackPayload(ctx context.Context, cmd *cobra.Command, input string, options unpackOptions) (err error) {
	if options.jobs < 1 {
		return fmt.Errorf("jobs must be greater than zero")
	}
	inputPath, err := filepath.Abs(input)
	if err != nil {
		return fmt.Errorf("resolve input %q: %w", input, err)
	}
	outputPath := options.output
	if outputPath == "" {
		base := strings.TrimSuffix(filepath.Base(inputPath), filepath.Ext(inputPath))
		outputPath = filepath.Join(filepath.Dir(inputPath), base+"_unpacked")
	}
	outputPath, err = filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolve output %q: %w", options.output, err)
	}
	oldPath := options.old
	if oldPath != "" {
		oldPath, err = filepath.Abs(oldPath)
		if err != nil {
			return fmt.Errorf("resolve source directory %q: %w", options.old, err)
		}
	}
	pl, err := payload.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open payload %q: %w", inputPath, err)
	}
	defer func() {
		if closeErr := pl.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close payload %q: %w", inputPath, closeErr)
		}
	}()
	selected := splitPartitions(options.partitions)
	items := selectedPayloadItems(pl.Partitions(), selected)
	var totalBytes uint64
	for _, item := range items {
		totalBytes += item.Bytes
	}
	extractOptions := payload.ExtractOptions{OutputDir: outputPath, Partitions: selected, Concurrency: options.jobs, SourceDir: oldPath, SkipVerify: options.noVerify}
	var bar *progress.Bar
	if !options.quiet && isTerminal(cmd.ErrOrStderr()) {
		tracker := progress.NewTracker(items)
		extractOptions.OnProgress = func(event payload.ProgressEvent) {
			tracker.Set(event.Partition, event.CompletedOps, event.Done && event.Err == nil)
		}
		bar = progress.Start(cmd.ErrOrStderr(), tracker, 200*time.Millisecond)
	}
	started := time.Now()
	extractErr := pl.Extract(ctx, extractOptions)
	if bar != nil {
		if stopErr := bar.Stop(); extractErr == nil && stopErr != nil {
			return fmt.Errorf("render progress: %w", stopErr)
		}
	}
	if extractErr != nil {
		return fmt.Errorf("extract payload %q: %w", inputPath, extractErr)
	}
	names := make([]string, 0, len(items))
	for _, item := range items {
		names = append(names, item.Name)
	}
	if err = registerImages(ctx, outputPath, names); err != nil {
		return err
	}
	if !options.quiet {
		elapsed := time.Since(started)
		throughput := float64(totalBytes) / (1024 * 1024) / elapsed.Seconds()
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\nelapsed %.3fs\nthroughput %.2f MiB/s\n", outputPath, elapsed.Seconds(), throughput)
	}
	return err
}

func selectedPayloadItems(partitions []payload.Partition, selected []string) []progress.Item {
	wanted := make(map[string]struct{}, len(selected))
	for _, name := range selected {
		wanted[name] = struct{}{}
	}
	items := make([]progress.Item, 0, len(partitions))
	for _, partition := range partitions {
		if _, ok := wanted[partition.Name]; len(wanted) == 0 || ok {
			items = append(items, progress.Item{Name: partition.Name, Bytes: partition.Size, Units: partition.TotalOperations})
		}
	}
	return items
}

func isTerminal(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func splitPartitions(value string) []string {
	if value == "" {
		return nil
	}
	seen := make(map[string]struct{})
	partitions := make([]string, 0)
	for _, name := range strings.Split(value, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		partitions = append(partitions, name)
	}
	return partitions
}
