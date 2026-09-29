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
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"artb/internal/avb"
	"artb/internal/buildinfo"
	"artb/internal/cpu"
	"artb/internal/detect"
	"artb/internal/executor"
	"artb/internal/nativebin"

	"github.com/spf13/cobra"
)

// magiskboot only sees these ASCII names relative to its working directory, so Unicode output paths stay safe.
const (
	bootOriginalName = "original.img"
	bootMetadataName = ".artb-boot.json"
	bootRamdiskCPIO  = "ramdisk.cpio"
	bootRamdiskDir   = "ramdisk"
	bootCPIOConfig   = "cpio"
	bootRepackName   = ".artb-repack.img"
	bootDTBDir       = "dtb_unpacked"
)

type bootMetadata struct {
	Version int    `json:"version"`
	Source  string `json:"source"`
	Type    string `json:"type"`
	Ramdisk string `json:"ramdisk_fingerprint,omitempty"`
	// RamdiskFormat 2 hashes contents only; the original format 0 also hashed modification times.
	RamdiskFormat int `json:"ramdisk_fingerprint_format,omitempty"`
}

const ramdiskContentFingerprint = 2

func newBootCommand() *cobra.Command {
	unpack, _ := newFormatUnpackCommand(detect.Boot, "unpack <boot.img>", "Split a boot image into kernel, ramdisk and dtb", "  artb boot unpack boot.img\n  artb boot unpack vendor_boot.img -o vendor_boot_unpacked", false, false)
	return newGroupCommand("boot", "Unpack and pack boot, init_boot, vendor_boot and recovery images", unpack, newBootPackCommand())
}

func newBootPackCommand() *cobra.Command {
	var output, keyPath, vbmetaPath string
	var quiet bool
	cmd := &cobra.Command{Use: "pack <unpacked-dir>", Short: "Rebuild a boot image from an unpacked directory", Long: "Rebuild a boot image with magiskboot.\n\nramdisk:\n  The ramdisk folder is repacked only when its content changed; otherwise the original ramdisk.cpio is kept.\n  The check uses ramdisk_fingerprint in .artb-boot.json.\n  It is a SHA-256 over the cpio mode config and each entry's path, type, permissions, size, link target and content.\n  Modification times are left out because the packed cpio stores them as 0.\n\nDevice trees:\n  If <dir>/dtb was split into <dir>/dtb_unpacked with artb dtb unpack, dtb is rebuilt first.\n\nAVB:\n  An AVB hash footer from the original image gets its size and digest recomputed.\n  --vbmeta checks whether a vbmeta image still records that digest; update it with artb vbmeta sync.", Example: "  artb boot pack boot_unpacked\n  artb boot pack boot_unpacked -o boot_new.img\n  artb boot pack boot_unpacked --avb-key rsa4096.pem", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Root().SilenceUsage = true
		return repackBoot(cmd.Context(), cmd, args[0], output, keyPath, vbmetaPath, quiet)
	}}
	cmd.Flags().StringVarP(&output, "output", "o", "", "Set output image path")
	cmd.Flags().StringVar(&vbmetaPath, "vbmeta", "", "Check that this vbmeta image records the new image digest")
	cmd.Flags().StringVar(&keyPath, "avb-key", "", "Re-sign a signed AVB footer with this RSA private key (PEM)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress success output")
	return cmd
}

func unpackBoot(ctx context.Context, cmd *cobra.Command, inputPath string, imageType detect.Type, options unpackOptions) error {
	started := time.Now()
	outputPath := options.output
	if outputPath == "" {
		outputPath = defaultOutput(inputPath)
	}
	outputPath, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolve output %q: %w", options.output, err)
	}
	if err = createEmptyDir(outputPath); err != nil {
		return err
	}
	executable, err := nativebin.New(buildinfo.Version).Ensure(ctx, "magiskboot")
	if err != nil {
		return err
	}
	if err = linkOrCopyFile(inputPath, filepath.Join(outputPath, bootOriginalName)); err != nil {
		return err
	}
	if err = runMagiskboot(ctx, executable, outputPath, "unpack", "-h", bootOriginalName); err != nil {
		return err
	}
	metadata := bootMetadata{Version: 1, Source: filepath.Base(inputPath), Type: string(imageType)}
	cpio, err := isNewcCPIO(filepath.Join(outputPath, bootRamdiskCPIO))
	if err != nil {
		return err
	}
	if cpio {
		if err = runMagiskboot(ctx, executable, outputPath, "cpio", bootRamdiskCPIO, "extract"); err != nil {
			return err
		}
		if metadata.Ramdisk, err = ramdiskFingerprint(outputPath, false); err != nil {
			return err
		}
		metadata.RamdiskFormat = ramdiskContentFingerprint
	}
	if err = writeBootMetadata(outputPath, metadata); err != nil {
		return err
	}
	if options.quiet {
		return nil
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\nelapsed %.3fs\n", outputPath, time.Since(started).Seconds())
	return err
}

func repackBoot(ctx context.Context, cmd *cobra.Command, dir, output, keyPath, vbmetaPath string, quiet bool) error {
	started := time.Now()
	dirPath, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve directory %q: %w", dir, err)
	}
	metadata, err := readBootMetadata(dirPath)
	if err != nil {
		return err
	}
	var key *rsa.PrivateKey
	if keyPath != "" {
		if key, err = avb.LoadKey(keyPath); err != nil {
			return err
		}
	}
	if output == "" {
		output = filepath.Join(filepath.Dir(dirPath), strings.TrimSuffix(metadata.Source, filepath.Ext(metadata.Source))+"_repacked.img")
	}
	outputPath, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("resolve output %q: %w", output, err)
	}
	executable, err := nativebin.New(buildinfo.Version).Ensure(ctx, "magiskboot")
	if err != nil {
		return err
	}
	if metadata.Ramdisk != "" {
		if _, statErr := os.Stat(filepath.Join(dirPath, bootRamdiskDir)); statErr == nil {
			fingerprint, err := ramdiskFingerprint(dirPath, metadata.RamdiskFormat != ramdiskContentFingerprint)
			if err != nil {
				return err
			}
			// An untouched ramdisk folder keeps the original cpio bytes so an unmodified repack is identical.
			if fingerprint != metadata.Ramdisk {
				if err = runMagiskboot(ctx, executable, dirPath, "cpio", "pack", "-c", bootCPIOConfig, bootRamdiskDir, bootRamdiskCPIO); err != nil {
					return err
				}
				if metadata.Ramdisk, err = ramdiskFingerprint(dirPath, false); err != nil {
					return err
				}
				metadata.RamdiskFormat = ramdiskContentFingerprint
				if err = writeBootMetadata(dirPath, metadata); err != nil {
					return err
				}
			}
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			return fmt.Errorf("inspect ramdisk directory: %w", statErr)
		}
	}
	// Device trees unpacked with artb dtb unpack into the default dtb_unpacked folder are rebuilt into dtb first.
	if _, err = os.Stat(filepath.Join(dirPath, bootDTBDir, deviceTreeMetadataName)); err == nil {
		if _, err = packDeviceTree(ctx, filepath.Join(dirPath, bootDTBDir), filepath.Join(dirPath, "dtb"), nil, true, cpu.Logical()); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("inspect %s: %w", bootDTBDir, err)
	}
	temporary := filepath.Join(dirPath, bootRepackName)
	if err = os.Remove(temporary); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove stale repack output: %w", err)
	}
	if err = runMagiskboot(ctx, executable, dirPath, "repack", bootOriginalName, bootRepackName); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err = moveFile(temporary, outputPath); err != nil {
		return err
	}
	// magiskboot copies the AVB footer and fixes its offsets but leaves the hash descriptor describing the old image.
	var footer *avb.FooterResult
	if meta, err := avb.Read(outputPath); err == nil && meta.Footer != nil && slices.ContainsFunc(meta.Descriptors, func(descriptor avb.Descriptor) bool { return descriptor.Kind == "hash" }) {
		if footer, err = avb.UpdateHashFooter(outputPath, key); err != nil {
			return err
		}
		if footer.StaleSignature {
			fmt.Fprintf(cmd.ErrOrStderr(), "%s: the AVB footer signature no longer matches; pass --avb-key to re-sign it\n", outputPath)
		}
	}
	report := cmd.OutOrStdout()
	if quiet {
		report = io.Discard
	}
	if err = checkVBMeta(report, cmd.ErrOrStderr(), vbmetaPath, outputPath); err != nil {
		return err
	}
	if quiet {
		return nil
	}
	text := outputPath + "\n"
	if footer != nil {
		meta, err := avb.Read(outputPath)
		if err != nil {
			return err
		}
		for _, descriptor := range meta.Descriptors {
			if descriptor.Kind == "hash" {
				text += fmt.Sprintf("avb %s image_size=%d digest=%s\n", descriptor.Partition, descriptor.ImageSize, descriptor.Digest)
			}
		}
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "%selapsed %.3fs\n", text, time.Since(started).Seconds())
	return err
}

func runMagiskboot(ctx context.Context, executable, dir string, args ...string) error {
	var output bytes.Buffer
	if _, err := executor.New(1).Run(ctx, executor.Spec{Name: executable, Args: args, Dir: dir, Stdout: &output, Stderr: &output}); err != nil {
		return fmt.Errorf("magiskboot %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(output.String()))
	}
	return nil
}

func createEmptyDir(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("read output directory: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("output directory %q is not empty", path)
	}
	return nil
}

func linkOrCopyFile(source, target string) (err error) {
	if os.Link(source, target) == nil {
		return nil
	}
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open %q: %w", source, err)
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create %q: %w", target, err)
	}
	defer func() {
		if closeErr := output.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close %q: %w", target, closeErr)
		}
	}()
	if _, err = io.CopyBuffer(output, input, make([]byte, 1<<20)); err != nil {
		return fmt.Errorf("copy %q: %w", source, err)
	}
	return nil
}

func moveFile(source, target string) error {
	if os.Rename(source, target) == nil {
		return nil
	}
	if err := linkOrCopyFile(source, target); err != nil {
		return err
	}
	if err := os.Remove(source); err != nil {
		return fmt.Errorf("remove %q: %w", source, err)
	}
	return nil
}

func isNewcCPIO(path string) (bool, error) {
	file, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("open ramdisk: %w", err)
	}
	defer file.Close()
	magic := make([]byte, 6)
	if _, err = io.ReadFull(file, magic); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil
		}
		return false, fmt.Errorf("read ramdisk: %w", err)
	}
	return string(magic) == "070701" || string(magic) == "070702", nil
}

// ramdiskFingerprint hashes the mode config, entry paths, types, permissions, sizes, symlink targets and contents; withTimes adds mtimes as format 0 did.
func ramdiskFingerprint(dir string, withTimes bool) (string, error) {
	digest := sha256.New()
	buffer := make([]byte, 1<<20)
	config, err := os.ReadFile(filepath.Join(dir, bootCPIOConfig))
	if err != nil {
		return "", fmt.Errorf("read cpio config: %w", err)
	}
	digest.Write(config)
	root := filepath.Join(dir, bootRamdiskDir)
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			_, err = fmt.Fprintf(digest, "%s\x00dir\n", filepath.ToSlash(relative))
			return err
		}
		// Windows directory listings cache size and mtime lazily, so read them from the file itself.
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if withTimes {
			_, err = fmt.Fprintf(digest, "%s\x00%d\x00%d\x00%d\n", filepath.ToSlash(relative), info.Mode(), info.Size(), info.ModTime().UnixNano())
		} else {
			_, err = fmt.Fprintf(digest, "%s\x00%d\x00%d\n", filepath.ToSlash(relative), info.Mode(), info.Size())
		}
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(digest, "%s\x00", target)
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.CopyBuffer(digest, file, buffer)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		_, err = digest.Write([]byte{0})
		return err
	})
	if err != nil {
		return "", fmt.Errorf("scan ramdisk directory: %w", err)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func readBootMetadata(dir string) (bootMetadata, error) {
	var metadata bootMetadata
	data, err := os.ReadFile(filepath.Join(dir, bootMetadataName))
	if err != nil {
		return metadata, fmt.Errorf("read boot metadata: %w", err)
	}
	if err = json.Unmarshal(data, &metadata); err != nil {
		return metadata, fmt.Errorf("parse boot metadata: %w", err)
	}
	if metadata.Version != 1 || metadata.Source == "" {
		return metadata, fmt.Errorf("unsupported boot metadata in %q", dir)
	}
	return metadata, nil
}

func writeBootMetadata(dir string, metadata bootMetadata) error {
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("encode boot metadata: %w", err)
	}
	if err = os.WriteFile(filepath.Join(dir, bootMetadataName), append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write boot metadata: %w", err)
	}
	return nil
}
