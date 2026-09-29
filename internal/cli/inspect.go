package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"artb/internal/avb"
	"artb/internal/bootimg"
	"artb/internal/cpu"
	"artb/internal/detect"
	"artb/internal/fdt"

	"github.com/spf13/cobra"
)

type inspectOutput struct {
	Path        string      `json:"path"`
	Type        detect.Type `json:"type"`
	Size        int64       `json:"size"`
	Boot        *bootInfo   `json:"boot,omitempty"`
	DTBO        *dtboInfo   `json:"dtbo,omitempty"`
	DeviceTrees []treeInfo  `json:"device_trees,omitempty"`
	AVB         *avbInfo    `json:"avb,omitempty"`
}

type sectionInfo struct {
	bootimg.Section
	SHA256 string `json:"sha256"`
}

type ramdiskInfo struct {
	bootimg.VendorRamdisk
	SHA256 string `json:"sha256"`
}

// bootInfo is the header of a boot or vendor_boot image with a digest per section.
type bootInfo struct {
	*bootimg.Image
	Sections       []sectionInfo `json:"sections"`
	VendorRamdisks []ramdiskInfo `json:"vendor_ramdisks,omitempty"`
}

type dtboInfo struct {
	Version    uint32 `json:"version"`
	PageSize   uint32 `json:"page_size"`
	TotalSize  uint32 `json:"total_size"`
	EntryCount uint32 `json:"entry_count"`
}

// treeInfo identifies one device tree; the DTBO fields are only set for overlay entries.
type treeInfo struct {
	Index       int         `json:"index"`
	Offset      int         `json:"offset"`
	Size        int         `json:"size"`
	SHA256      string      `json:"sha256"`
	ID          *uint32     `json:"id,omitempty"`
	Rev         *uint32     `json:"rev,omitempty"`
	Custom      []uint32    `json:"custom,omitempty"`
	Compression string      `json:"compression,omitempty"`
	Summary     fdt.Summary `json:"tree"`
}

// avbInfo is the AVB footer and vbmeta summary; DigestMatches is set for hash descriptors after rehashing the image.
type avbInfo struct {
	Footer        *avb.Footer      `json:"footer,omitempty"`
	Algorithm     string           `json:"algorithm"`
	RollbackIndex uint64           `json:"rollback_index"`
	Flags         uint32           `json:"flags"`
	Descriptors   []avb.Descriptor `json:"descriptors"`
	DigestMatches *bool            `json:"digest_matches,omitempty"`
}

var compressionNames = map[uint32]string{0: "none", 1: "zlib", 2: "gzip"}

// inspectFile gathers everything artb knows about an image without modifying it.
func inspectFile(path string) (*inspectOutput, error) {
	result, err := detect.File(path)
	if err != nil {
		return nil, err
	}
	output := &inspectOutput{Path: path, Type: result.Type, Size: result.Size}
	var image *deviceTreeImage
	switch result.Type {
	case detect.Boot, detect.VendorBoot, detect.DTB, detect.DTBO:
		if image, err = loadDeviceTreeImage(path); err != nil {
			return nil, err
		}
		if image.boot != nil {
			info := &bootInfo{Image: image.boot}
			for _, section := range image.boot.Sections {
				info.Sections = append(info.Sections, sectionInfo{Section: section, SHA256: sha256Hex(image.data[section.Offset : section.Offset+section.Size])})
			}
			for _, ramdisk := range image.boot.VendorRamdisks {
				info.VendorRamdisks = append(info.VendorRamdisks, ramdiskInfo{VendorRamdisk: ramdisk, SHA256: sha256Hex(image.data[ramdisk.Offset : ramdisk.Offset+ramdisk.Size])})
			}
			output.Boot = info
		}
		if image.table != nil {
			output.DTBO = &dtboInfo{Version: image.table.Version, PageSize: image.table.PageSize, TotalSize: image.table.TotalSize, EntryCount: image.table.EntryCount}
		}
		for _, tree := range image.trees {
			info := treeInfo{Index: tree.Index, Offset: tree.Offset, Size: len(tree.Blob), SHA256: sha256Hex(tree.Blob), Summary: tree.Tree.Summarize()}
			if tree.Entry != nil {
				id, rev := tree.Entry.ID, tree.Entry.Rev
				info.ID, info.Rev, info.Custom = &id, &rev, tree.Entry.Custom[:]
				info.Offset, info.Size = int(tree.Entry.Offset), int(tree.Entry.Size)
				info.Compression = compressionNames[tree.Entry.Compression(image.table.Version)]
			}
			output.DeviceTrees = append(output.DeviceTrees, info)
		}
	}
	if raw, err := avb.ReadRaw(path); err == nil {
		meta, err := avb.Parse(raw.Blob)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		info := &avbInfo{Footer: raw.Footer, Algorithm: meta.Algorithm, RollbackIndex: meta.RollbackIndex, Flags: meta.Flags, Descriptors: meta.Descriptors}
		for _, descriptor := range meta.Descriptors {
			if descriptor.Kind == "hash" && raw.Footer != nil {
				_, verifyErr := avb.VerifyFooter(path, cpu.Logical())
				matches := verifyErr == nil
				info.DigestMatches = &matches
				break
			}
		}
		output.AVB = info
	}
	return output, nil
}

func formatCells(cells []uint32) string {
	parts := make([]string, len(cells))
	for index, cell := range cells {
		parts[index] = fmt.Sprintf("0x%x", cell)
	}
	return "<" + strings.Join(parts, " ") + ">"
}

func treeLine(info treeInfo) string {
	var fields []string
	if info.ID != nil {
		fields = append(fields, fmt.Sprintf("id=0x%x rev=0x%x custom=%s compression=%s", *info.ID, *info.Rev, formatCells(info.Custom), info.Compression))
	}
	fields = append(fields, fmt.Sprintf("offset=%d size=%d", info.Offset, info.Size))
	if info.Summary.Model != "" {
		fields = append(fields, fmt.Sprintf("model=%q", info.Summary.Model))
	}
	for _, field := range []struct {
		name  string
		cells []uint32
	}{{"msm_id", info.Summary.MsmID}, {"board_id", info.Summary.BoardID}, {"pmic_id", info.Summary.PmicID}} {
		if len(field.cells) > 0 {
			fields = append(fields, field.name+"="+formatCells(field.cells))
		}
	}
	return strings.Join(fields, " ")
}

func printInspect(out io.Writer, output *inspectOutput) error {
	var builder strings.Builder
	fmt.Fprintf(&builder, "path %s\ntype %s\nsize %d\n", output.Path, output.Type, output.Size)
	if boot := output.Boot; boot != nil {
		fmt.Fprintf(&builder, "header_version %d\nheader_size %d\npage_size %d\n", boot.HeaderVersion, boot.HeaderSize, boot.PageSize)
		for _, field := range []struct {
			name  string
			value string
		}{{"os_version", boot.OSVersion}, {"os_patch_level", boot.OSPatchLevel}, {"name", boot.Name}, {"id", boot.ID}} {
			if field.value != "" {
				fmt.Fprintf(&builder, "%s %s\n", field.name, field.value)
			}
		}
		for _, field := range []struct {
			name  string
			value uint64
		}{{"kernel_addr", uint64(boot.KernelAddr)}, {"ramdisk_addr", uint64(boot.RamdiskAddr)}, {"second_addr", uint64(boot.SecondAddr)}, {"tags_addr", uint64(boot.TagsAddr)}, {"dtb_addr", boot.DTBAddr}} {
			if field.value != 0 {
				fmt.Fprintf(&builder, "%s 0x%x\n", field.name, field.value)
			}
		}
		fmt.Fprintf(&builder, "cmdline %s\n", boot.Cmdline)
		if boot.ExtraCmdline != "" {
			fmt.Fprintf(&builder, "extra_cmdline %s\n", boot.ExtraCmdline)
		}
		for _, section := range boot.Sections {
			fmt.Fprintf(&builder, "section %s offset=%d size=%d sha256=%s\n", section.Name, section.Offset, section.Size, section.SHA256)
		}
		for index, ramdisk := range boot.VendorRamdisks {
			board := ""
			if slices.ContainsFunc(ramdisk.BoardID, func(word uint32) bool { return word != 0 }) {
				board = " board_id=" + formatCells(ramdisk.BoardID)
			}
			fmt.Fprintf(&builder, "vendor_ramdisk %d name=%q type=%s offset=%d size=%d%s sha256=%s\n", index, ramdisk.Name, ramdisk.Type, ramdisk.Offset, ramdisk.Size, board, ramdisk.SHA256)
		}
		for _, line := range strings.Split(strings.TrimRight(boot.Bootconfig, "\x00\n"), "\n") {
			if line != "" {
				fmt.Fprintf(&builder, "bootconfig %s\n", line)
			}
		}
	}
	if dtbo := output.DTBO; dtbo != nil {
		fmt.Fprintf(&builder, "dtbo version=%d page_size=%d total_size=%d entries=%d\n", dtbo.Version, dtbo.PageSize, dtbo.TotalSize, dtbo.EntryCount)
	}
	if len(output.DeviceTrees) > 0 {
		fmt.Fprintf(&builder, "trees %d\n", len(output.DeviceTrees))
		for _, tree := range output.DeviceTrees {
			fmt.Fprintf(&builder, "tree %02d %s\n", tree.Index, treeLine(tree))
		}
	}
	if info := output.AVB; info != nil {
		if footer := info.Footer; footer != nil {
			fmt.Fprintf(&builder, "avb footer original_image_size=%d vbmeta_offset=%d vbmeta_size=%d\n", footer.OriginalImageSize, footer.VBMetaOffset, footer.VBMetaSize)
		}
		fmt.Fprintf(&builder, "avb algorithm=%s rollback_index=%d flags=%d\n", info.Algorithm, info.RollbackIndex, info.Flags)
		for _, descriptor := range info.Descriptors {
			switch descriptor.Kind {
			case "hash":
				line := fmt.Sprintf("avb hash %s image_size=%d hash_algorithm=%s digest=%s", descriptor.Partition, descriptor.ImageSize, descriptor.HashAlgorithm, descriptor.Digest)
				if info.DigestMatches != nil && info.Footer != nil {
					line += fmt.Sprintf(" matches=%t", *info.DigestMatches)
				}
				fmt.Fprintln(&builder, line)
			case "hashtree":
				fmt.Fprintf(&builder, "avb hashtree %s image_size=%d hash_algorithm=%s root_digest=%s\n", descriptor.Partition, descriptor.ImageSize, descriptor.HashAlgorithm, descriptor.Digest)
			case "property":
				fmt.Fprintf(&builder, "avb property %s=%s\n", descriptor.Key, descriptor.Value)
			case "chain":
				fmt.Fprintf(&builder, "avb chain %s rollback_index_location=%d public_key_sha1=%s\n", descriptor.Partition, descriptor.RollbackIndexLocation, descriptor.PublicKeySHA1)
			case "cmdline":
				fmt.Fprintf(&builder, "avb cmdline %s\n", descriptor.Cmdline)
			default:
				fmt.Fprintf(&builder, "avb %s\n", descriptor.Kind)
			}
		}
	}
	_, err := io.WriteString(out, builder.String())
	return err
}

func newInspectCommand() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{Use: "inspect <file>", Short: "Identify an Android image and show its layout", Long: "Identify an image and show how it is laid out.\n\nboot and vendor_boot:\n  Header version, page size, load addresses and cmdline.\n  Offset, size and SHA-256 of every section.\n  The vendor ramdisk table and bootconfig.\n\nDevice trees (dtb, DTBO and the dtb section of boot images):\n  Offset, size, model, qcom,msm-id, qcom,board-id and qcom,pmic-id of every tree.\n\nImages with an AVB footer:\n  The footer and descriptors; a hash descriptor is checked against the image.\n\n--json prints the same data for scripts.", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Root().SilenceUsage = true
		path, err := filepath.Abs(args[0])
		if err != nil {
			return fmt.Errorf("resolve %q: %w", args[0], err)
		}
		output, err := inspectFile(path)
		if err != nil {
			return err
		}
		if jsonOutput {
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetEscapeHTML(false)
			return encoder.Encode(output)
		}
		return printInspect(cmd.OutOrStdout(), output)
	}}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Print JSON output")
	return cmd
}
