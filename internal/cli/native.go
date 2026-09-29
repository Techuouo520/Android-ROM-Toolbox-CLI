package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"artb/internal/buildinfo"
	"artb/internal/detect"
	"artb/internal/executor"
	"artb/internal/nativebin"
	"artb/internal/progress"
	"artb/internal/workspace"

	"github.com/spf13/cobra"
)

func newSparseCommand() *cobra.Command {
	return newGroupCommand("sparse", "Convert Android sparse images", newSparseToRawCommand(), newSparseToSparseCommand())
}

func newSparseToRawCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "to-raw <sparse.img> <raw.img>", Short: "Convert a sparse image to raw", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Root().SilenceUsage = true
		return runNativeConversion(cmd.Context(), cmd, "simg2img", args[0], args[1], "")
	}}
	return cmd
}

func newSparseToSparseCommand() *cobra.Command {
	var blockSize uint32
	cmd := &cobra.Command{Use: "to-sparse <raw.img> <sparse.img>", Short: "Convert a raw image to sparse", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Root().SilenceUsage = true
		block := ""
		if blockSize > 0 {
			block = strconv.FormatUint(uint64(blockSize), 10)
		}
		return runNativeConversion(cmd.Context(), cmd, "img2simg", args[0], args[1], block)
	}}
	cmd.Flags().Uint32Var(&blockSize, "block-size", 0, "Set sparse block size")
	return cmd
}

func runNativeConversion(ctx context.Context, cmd *cobra.Command, tool, input, output, extra string) error {
	inputPath, err := filepath.Abs(input)
	if err != nil {
		return fmt.Errorf("resolve input %q: %w", input, err)
	}
	outputPath, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("resolve output %q: %w", output, err)
	}
	if err = os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	executable, err := nativebin.New(buildinfo.Version).Ensure(ctx, tool)
	if err != nil {
		return err
	}
	arguments := []string{inputPath, outputPath}
	if extra != "" {
		arguments = append(arguments, extra)
	}
	if _, err = executor.New(1).Run(ctx, executor.Spec{Name: executable, Args: arguments, Stdout: cmd.OutOrStdout(), Stderr: cmd.ErrOrStderr()}); err != nil {
		return err
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), outputPath)
	return err
}

func unpackDetected(ctx context.Context, cmd *cobra.Command, input string, options unpackOptions) error {
	inputPath, err := filepath.Abs(input)
	if err != nil {
		return fmt.Errorf("resolve input %q: %w", input, err)
	}
	result, err := detect.File(inputPath)
	if err != nil {
		return err
	}
	if err = checkExpected(inputPath, result.Type, options); err != nil {
		return err
	}
	switch result.Type {
	case detect.Payload, detect.ZIP:
		return unpackPayload(ctx, cmd, inputPath, options)
	case detect.Super:
		return unpackSuper(ctx, cmd, inputPath, options)
	case detect.EROFS:
		return unpackEROFS(ctx, cmd, inputPath, options)
	case detect.Ext4:
		return unpackEXT4(ctx, cmd, inputPath, options)
	case detect.F2FS:
		return unpackFilesystem(ctx, cmd, inputPath, options, "f2fs", "extract.f2fs", nil)
	case detect.Sparse:
		return unpackSparse(ctx, cmd, inputPath, options)
	case detect.Boot, detect.VendorBoot:
		return unpackBoot(ctx, cmd, inputPath, result.Type, options)
	case detect.DTBO, detect.DTB:
		return unpackDeviceTree(ctx, cmd, inputPath, result.Type, options)
	default:
		return fmt.Errorf("unpack %q: unsupported input type %s", inputPath, result.Type)
	}
}

// checkExpected lets format commands refuse other formats; sparse input is judged after it is read or expanded.
func checkExpected(inputPath string, kind detect.Type, options unpackOptions) error {
	switch kind {
	case detect.ZIP:
		kind = detect.Payload
	case detect.VendorBoot:
		kind = detect.Boot
	}
	if options.expect == "" || kind == detect.Sparse || kind == options.expect {
		return nil
	}
	source := inputPath
	if options.source != "" {
		source = options.source
	}
	return fmt.Errorf("%q is %s, not %s; use artb unpack to detect the format", source, kind, options.expect)
}

func defaultOutput(inputPath string) string {
	base := strings.TrimSuffix(filepath.Base(inputPath), filepath.Ext(inputPath))
	return filepath.Join(filepath.Dir(inputPath), base+"_unpacked")
}

func sparseIsSuper(path string) (isSuper bool, err error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close sparse image: %w", closeErr)
		}
	}()
	var header [28]byte
	if _, err = file.ReadAt(header[:], 0); err != nil {
		return false, fmt.Errorf("read sparse header: %w", err)
	}
	le := binary.LittleEndian
	blockSize, totalChunks := le.Uint32(header[12:16]), le.Uint32(header[20:24])
	fileHeader, chunkHeader := le.Uint16(header[8:10]), le.Uint16(header[10:12])
	if le.Uint32(header[:4]) != 0xed26ff3a || fileHeader < 28 || chunkHeader < 12 || blockSize == 0 {
		return false, fmt.Errorf("invalid sparse header in %q", path)
	}
	const geometryOffset = uint64(4096)
	logical, physical := uint64(0), int64(fileHeader)
	var magic [4]byte
	var found [4]bool
	for i := uint32(0); i < totalChunks && logical < geometryOffset+4; i++ {
		var chunk [12]byte
		if _, err = file.ReadAt(chunk[:], physical); err != nil {
			return false, fmt.Errorf("read sparse chunk: %w", err)
		}
		kind, count, total := le.Uint16(chunk[:2]), le.Uint32(chunk[4:8]), le.Uint32(chunk[8:12])
		if total < uint32(chunkHeader) {
			return false, fmt.Errorf("invalid sparse chunk size in %q", path)
		}
		payload := uint64(total - uint32(chunkHeader))
		length := uint64(count) * uint64(blockSize)
		if kind == 0xcac4 {
			if payload != 4 || count != 0 {
				return false, fmt.Errorf("invalid sparse CRC chunk in %q", path)
			}
			physical += int64(total)
			continue
		}
		if (kind == 0xcac1 && payload != length) || (kind == 0xcac2 && payload != 4) || (kind == 0xcac3 && payload != 0) || (kind != 0xcac1 && kind != 0xcac2 && kind != 0xcac3) {
			return false, fmt.Errorf("invalid sparse chunk in %q", path)
		}
		start, end := logical, logical+length
		if start < geometryOffset {
			start = geometryOffset
		}
		if end > geometryOffset+4 {
			end = geometryOffset + 4
		}
		if start < end {
			part := magic[start-geometryOffset : end-geometryOffset]
			switch kind {
			case 0xcac1:
				if _, err = file.ReadAt(part, physical+int64(chunkHeader)+int64(start-logical)); err != nil {
					return false, fmt.Errorf("read sparse geometry: %w", err)
				}
			case 0xcac2:
				var pattern [4]byte
				if _, err = file.ReadAt(pattern[:], physical+int64(chunkHeader)); err != nil {
					return false, fmt.Errorf("read sparse fill: %w", err)
				}
				for j := range part {
					part[j] = pattern[(start-logical+uint64(j))%4]
				}
			}
			for j := start; j < end; j++ {
				found[j-geometryOffset] = true
			}
		}
		logical += length
		physical += int64(total)
	}
	for _, ok := range found {
		if !ok {
			return false, nil
		}
	}
	return string(magic[:]) == "gDla", nil
}

// unpackSparse expands a sparse filesystem image, while sparse super is read directly.
func unpackSparse(ctx context.Context, cmd *cobra.Command, inputPath string, options unpackOptions) (err error) {
	source := inputPath
	if options.source != "" {
		source = options.source
	}
	isSuper, err := sparseIsSuper(inputPath)
	if err != nil {
		return err
	}
	if isSuper {
		options.source, options.sparse = source, true
		if err = checkExpected(inputPath, detect.Super, options); err != nil {
			return err
		}
		return unpackSuper(ctx, cmd, inputPath, options)
	}
	outputPath := options.output
	if outputPath == "" {
		outputPath = defaultOutput(source)
		if directory := filepath.Dir(source); workspace.Exists(directory) {
			outputPath = directory
		}
	}
	outputPath, err = filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolve output %q: %w", options.output, err)
	}
	if err = os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create output parent: %w", err)
	}
	workDir, err := os.MkdirTemp(filepath.Dir(outputPath), ".artb-sparse-")
	if err != nil {
		return fmt.Errorf("create sparse work directory: %w", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(workDir); err == nil && removeErr != nil {
			err = fmt.Errorf("remove sparse work directory: %w", removeErr)
		}
	}()
	rawPath := filepath.Join(workDir, filepath.Base(inputPath))
	executable, err := nativebin.New(buildinfo.Version).Ensure(ctx, "simg2img")
	if err != nil {
		return err
	}
	var nativeStderr bytes.Buffer
	if _, err = executor.New(1).Run(ctx, executor.Spec{Name: executable, Args: []string{inputPath, rawPath}, Stderr: &nativeStderr}); err != nil {
		return fmt.Errorf("convert sparse %q: %w: %s", inputPath, err, strings.TrimSpace(nativeStderr.String()))
	}
	result, err := detect.File(rawPath)
	if err != nil {
		return err
	}
	if result.Type == detect.Sparse {
		return fmt.Errorf("unpack %q: sparse image expands to another sparse image", inputPath)
	}
	options.output, options.source, options.sparse = outputPath, source, true
	return unpackDetected(ctx, cmd, rawPath, options)
}

func unpackEXT4(ctx context.Context, cmd *cobra.Command, inputPath string, options unpackOptions) error {
	return unpackFilesystem(ctx, cmd, inputPath, options, "ext4", "extract.ext4", nil)
}

func unpackEROFS(ctx context.Context, cmd *cobra.Command, inputPath string, options unpackOptions) error {
	return unpackFilesystem(ctx, cmd, inputPath, options, "erofs", "extract.erofs", []string{"-x", "-s"})
}

// unpackFilesystem extracts a partition tree plus its configs and records the image parameters in the workspace.
func unpackFilesystem(ctx context.Context, cmd *cobra.Command, inputPath string, options unpackOptions, kind, tool string, extra []string) error {
	if options.jobs < 1 {
		return fmt.Errorf("jobs must be greater than zero")
	}
	outputPath, err := partitionOutput(options, inputPath)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(outputPath, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err = ensureFreshTree(outputPath, imageName(inputPath)); err != nil {
		return err
	}
	executable, err := nativebin.New(buildinfo.Version).Ensure(ctx, tool)
	if err != nil {
		return err
	}
	arguments := append([]string{"-i", inputPath, "-o", outputPath}, extra...)
	arguments = append(arguments, "-T"+strconv.Itoa(options.jobs), "--artb-progress")
	register := func() error { return registerFilesystem(ctx, outputPath, kind, inputPath, options) }
	return runNativeExtraction(ctx, cmd, executable, arguments, outputPath, options.quiet, fmt.Sprintf("extract %s %q", kind, inputPath), register)
}

func runNativeExtraction(ctx context.Context, cmd *cobra.Command, executable string, arguments []string, outputPath string, quiet bool, action string, finish func() error) error {
	var nativeStdout bytes.Buffer
	var nativeStderr bytes.Buffer
	gauge := &progress.Gauge{}
	reports := progress.NewReportWriter(gauge, &nativeStdout)
	var bar *progress.Bar
	if !quiet && isTerminal(cmd.ErrOrStderr()) {
		bar = progress.Start(cmd.ErrOrStderr(), gauge, 200*time.Millisecond)
	}
	started := time.Now()
	_, runErr := executor.New(1).Run(ctx, executor.Spec{Name: executable, Args: arguments, Stdout: reports, Stderr: &nativeStderr})
	elapsed := time.Since(started)
	flushErr := reports.Flush()
	if bar != nil {
		if stopErr := bar.Stop(); runErr == nil && stopErr != nil {
			return fmt.Errorf("render progress: %w", stopErr)
		}
	}
	if runErr != nil {
		message := strings.TrimSpace(strings.Join([]string{nativeStdout.String(), nativeStderr.String()}, "\n"))
		if message == "" {
			return fmt.Errorf("%s: %w", action, runErr)
		}
		return fmt.Errorf("%s: %w: %s", action, runErr, message)
	}
	if flushErr != nil {
		return fmt.Errorf("%s: %w", action, flushErr)
	}
	if finish != nil {
		if err := finish(); err != nil {
			return fmt.Errorf("%s: %w", action, err)
		}
	}
	if quiet {
		return nil
	}
	throughput := float64(gauge.Snapshot().Bytes) / (1024 * 1024) / elapsed.Seconds()
	_, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\nelapsed %.3fs\nthroughput %.2f MiB/s\n", outputPath, elapsed.Seconds(), throughput)
	return err
}

func unpackSuper(ctx context.Context, cmd *cobra.Command, inputPath string, options unpackOptions) (err error) {
	if options.jobs < 1 {
		return fmt.Errorf("jobs must be greater than zero")
	}
	source := inputPath
	if options.source != "" {
		source = options.source
	}
	outputPath := options.output
	if outputPath == "" {
		outputPath = defaultOutput(source)
	}
	outputPath, err = filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolve output %q: %w", options.output, err)
	}
	if err = os.MkdirAll(outputPath, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	executable, err := nativebin.New(buildinfo.Version).Ensure(ctx, "lpunpack")
	if err != nil {
		return err
	}
	metadataPath := filepath.Join(outputPath, ".artb-super-metadata.json")
	defer func() {
		if removeErr := os.Remove(metadataPath); err == nil && removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			err = fmt.Errorf("remove super metadata: %w", removeErr)
		}
	}()
	arguments := []string{"-j", strconv.Itoa(options.jobs), "--artb-progress", "--artb-metadata=" + metadataPath}
	for _, partition := range splitPartitions(options.partitions) {
		arguments = append(arguments, "-p", partition)
	}
	arguments = append(arguments, inputPath, outputPath)
	register := func() error { return registerSuper(ctx, outputPath, source, options.sparse, metadataPath) }
	return runNativeExtraction(ctx, cmd, executable, arguments, outputPath, options.quiet, fmt.Sprintf("extract super %q", inputPath), register)
}
