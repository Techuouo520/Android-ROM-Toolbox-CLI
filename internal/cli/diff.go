package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"artb/internal/avb"
	"artb/internal/bootimg"
	"artb/internal/detect"
	"artb/internal/fdt"

	"github.com/spf13/cobra"
)

type fileSummary struct {
	Path   string      `json:"path"`
	Type   detect.Type `json:"type"`
	Size   int64       `json:"size"`
	SHA256 string      `json:"sha256"`
}

type fieldChange struct {
	Field string `json:"field"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

// regionDiff compares one section or vendor ramdisk; Status is same, different, added or removed.
type regionDiff struct {
	Name    string        `json:"name"`
	Status  string        `json:"status"`
	OldSize int64         `json:"old_size,omitempty"`
	NewSize int64         `json:"new_size,omitempty"`
	Fields  []fieldChange `json:"fields,omitempty"`
}

// treeDiff compares one device tree; Status is same, equivalent (bytes differ, content does not), different, added or removed.
type treeDiff struct {
	Index    int           `json:"index"`
	Status   string        `json:"status"`
	OldModel string        `json:"old_model,omitempty"`
	NewModel string        `json:"new_model,omitempty"`
	Fields   []fieldChange `json:"fields,omitempty"`
	Changes  []fdt.Change  `json:"changes,omitempty"`
}

type diffReport struct {
	Old               fileSummary   `json:"old"`
	New               fileSummary   `json:"new"`
	Identical         bool          `json:"identical"`
	Header            []fieldChange `json:"header,omitempty"`
	Sections          []regionDiff  `json:"sections,omitempty"`
	VendorRamdisks    []regionDiff  `json:"vendor_ramdisks,omitempty"`
	BootconfigRemoved []string      `json:"bootconfig_removed,omitempty"`
	BootconfigAdded   []string      `json:"bootconfig_added,omitempty"`
	OldTrees          int           `json:"old_trees"`
	NewTrees          int           `json:"new_trees"`
	Trees             []treeDiff    `json:"trees,omitempty"`
	AVB               []fieldChange `json:"avb,omitempty"`
}

func summarizeFile(path string, kind detect.Type) (fileSummary, error) {
	file, err := os.Open(path)
	if err != nil {
		return fileSummary{}, err
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.CopyBuffer(digest, file, make([]byte, 1<<20))
	if err != nil {
		return fileSummary{}, fmt.Errorf("hash %s: %w", path, err)
	}
	return fileSummary{Path: path, Type: kind, Size: size, SHA256: hex.EncodeToString(digest.Sum(nil))}, nil
}

func compareField(changes []fieldChange, field, old, new string) []fieldChange {
	if old != new {
		changes = append(changes, fieldChange{Field: field, Old: old, New: new})
	}
	return changes
}

// headerFields lists the decoded header values, including the size field of every section, in header order.
func headerFields(image *bootimg.Image) [][2]string {
	fields := [][2]string{{"header_version", fmt.Sprint(image.HeaderVersion)}, {"header_size", fmt.Sprint(image.HeaderSize)}, {"page_size", fmt.Sprint(image.PageSize)}, {"os_version", image.OSVersion}, {"os_patch_level", image.OSPatchLevel}, {"name", image.Name}, {"cmdline", image.Cmdline}, {"extra_cmdline", image.ExtraCmdline}, {"kernel_addr", fmt.Sprintf("0x%x", image.KernelAddr)}, {"ramdisk_addr", fmt.Sprintf("0x%x", image.RamdiskAddr)}, {"second_addr", fmt.Sprintf("0x%x", image.SecondAddr)}, {"tags_addr", fmt.Sprintf("0x%x", image.TagsAddr)}, {"dtb_addr", fmt.Sprintf("0x%x", image.DTBAddr)}, {"id", image.ID}}
	for _, section := range image.Sections {
		if section.Name != "header" {
			fields = append(fields, [2]string{section.Name + "_size", fmt.Sprint(section.Size)})
		}
	}
	if image.Vendor && image.HeaderVersion >= 4 {
		fields = append(fields, [2]string{"vendor_ramdisk_table_entries", fmt.Sprint(len(image.VendorRamdisks))})
	}
	return fields
}

// byteRanges renders the offsets where a and b differ as start-end ranges.
func byteRanges(a, b []byte) string {
	var ranges []string
	start := -1
	for index := 0; index <= max(len(a), len(b)); index++ {
		differs := index < max(len(a), len(b)) && (index >= len(a) || index >= len(b) || a[index] != b[index])
		switch {
		case differs && start < 0:
			start = index
		case !differs && start >= 0:
			ranges = append(ranges, fmt.Sprintf("%d-%d", start, index-1))
			start = -1
		}
	}
	return strings.Join(ranges, ",")
}

func diffBoot(report *diffReport, old, new *deviceTreeImage) {
	oldFields, newFields := headerFields(old.boot), headerFields(new.boot)
	newValues := map[string]string{}
	for _, field := range newFields {
		newValues[field[0]] = field[1]
	}
	for _, field := range oldFields {
		report.Header = compareField(report.Header, field[0], field[1], newValues[field[0]])
		delete(newValues, field[0])
	}
	for _, field := range newFields {
		if _, extra := newValues[field[0]]; extra {
			report.Header = compareField(report.Header, field[0], "", field[1])
		}
	}
	oldHeader, _ := old.boot.Section("header")
	newHeader, _ := new.boot.Section("header")
	if oldBytes, newBytes := old.data[:oldHeader.Size], new.data[:newHeader.Size]; len(report.Header) == 0 && !bytes.Equal(oldBytes, newBytes) {
		report.Header = append(report.Header, fieldChange{Field: "other bytes", New: byteRanges(oldBytes, newBytes)})
	}
	names := []string{}
	for _, image := range []*bootimg.Image{old.boot, new.boot} {
		for _, section := range image.Sections {
			if !slices.Contains(names, section.Name) {
				names = append(names, section.Name)
			}
		}
	}
	for _, name := range names {
		oldSection, oldOK := old.boot.Section(name)
		newSection, newOK := new.boot.Section(name)
		region := regionDiff{Name: name, OldSize: oldSection.Size, NewSize: newSection.Size}
		switch {
		case !newOK:
			region.Status = "removed"
		case !oldOK:
			region.Status = "added"
		case bytes.Equal(old.data[oldSection.Offset:oldSection.Offset+oldSection.Size], new.data[newSection.Offset:newSection.Offset+newSection.Size]):
			region.Status = "same"
		default:
			region.Status = "different"
		}
		report.Sections = append(report.Sections, region)
	}
	for index := range max(len(old.boot.VendorRamdisks), len(new.boot.VendorRamdisks)) {
		region := regionDiff{Name: fmt.Sprint(index)}
		switch {
		case index >= len(new.boot.VendorRamdisks):
			region.Status, region.OldSize = "removed", old.boot.VendorRamdisks[index].Size
		case index >= len(old.boot.VendorRamdisks):
			region.Status, region.NewSize = "added", new.boot.VendorRamdisks[index].Size
		default:
			a, b := old.boot.VendorRamdisks[index], new.boot.VendorRamdisks[index]
			region.OldSize, region.NewSize, region.Status = a.Size, b.Size, "same"
			region.Fields = compareField(region.Fields, "name", a.Name, b.Name)
			region.Fields = compareField(region.Fields, "type", a.Type, b.Type)
			region.Fields = compareField(region.Fields, "board_id", formatCells(a.BoardID), formatCells(b.BoardID))
			if len(region.Fields) > 0 || !bytes.Equal(old.data[a.Offset:a.Offset+a.Size], new.data[b.Offset:b.Offset+b.Size]) {
				region.Status = "different"
			}
		}
		report.VendorRamdisks = append(report.VendorRamdisks, region)
	}
	oldLines, newLines := strings.Split(strings.TrimRight(old.boot.Bootconfig, "\x00\n"), "\n"), strings.Split(strings.TrimRight(new.boot.Bootconfig, "\x00\n"), "\n")
	for _, line := range oldLines {
		if line != "" && !slices.Contains(newLines, line) {
			report.BootconfigRemoved = append(report.BootconfigRemoved, line)
		}
	}
	for _, line := range newLines {
		if line != "" && !slices.Contains(oldLines, line) {
			report.BootconfigAdded = append(report.BootconfigAdded, line)
		}
	}
}

func diffTrees(report *diffReport, old, new *deviceTreeImage) {
	report.OldTrees, report.NewTrees = len(old.trees), len(new.trees)
	for index := range max(len(old.trees), len(new.trees)) {
		diff := treeDiff{Index: index}
		switch {
		case index >= len(new.trees):
			diff.Status, diff.OldModel = "removed", old.trees[index].Tree.Summarize().Model
		case index >= len(old.trees):
			diff.Status, diff.NewModel = "added", new.trees[index].Tree.Summarize().Model
		default:
			a, b := old.trees[index], new.trees[index]
			diff.OldModel, diff.NewModel = a.Tree.Summarize().Model, b.Tree.Summarize().Model
			if a.Entry != nil && b.Entry != nil {
				diff.Fields = compareField(diff.Fields, "id", fmt.Sprintf("0x%x", a.Entry.ID), fmt.Sprintf("0x%x", b.Entry.ID))
				diff.Fields = compareField(diff.Fields, "rev", fmt.Sprintf("0x%x", a.Entry.Rev), fmt.Sprintf("0x%x", b.Entry.Rev))
				diff.Fields = compareField(diff.Fields, "custom", formatCells(a.Entry.Custom[:]), formatCells(b.Entry.Custom[:]))
			}
			diff.Changes = fdt.Diff(a.Tree.Root, b.Tree.Root)
			switch {
			case bytes.Equal(a.Blob, b.Blob) && len(diff.Fields) == 0:
				diff.Status = "same"
			case len(diff.Changes) == 0 && len(diff.Fields) == 0:
				diff.Status = "equivalent"
			default:
				diff.Status = "different"
			}
		}
		report.Trees = append(report.Trees, diff)
	}
}

func readVBMeta(path string) *avb.VBMeta {
	meta, err := avb.Read(path)
	if err != nil {
		return nil
	}
	return meta
}

// descriptorKey names a descriptor so the same one can be found in both images.
func descriptorKey(descriptor avb.Descriptor) string {
	switch descriptor.Kind {
	case "property":
		return "property " + descriptor.Key
	case "cmdline":
		return "cmdline " + descriptor.Cmdline
	}
	return descriptor.Kind + " " + descriptor.Partition
}

func diffAVB(old, new *avb.VBMeta) []fieldChange {
	var changes []fieldChange
	if old == nil && new == nil {
		return nil
	}
	if old == nil || new == nil {
		state := func(meta *avb.VBMeta) string {
			if meta == nil {
				return "none"
			}
			return "present"
		}
		return []fieldChange{{Field: "vbmeta", Old: state(old), New: state(new)}}
	}
	footer := func(meta *avb.VBMeta) string {
		if meta.Footer == nil {
			return "none"
		}
		return fmt.Sprintf("original_image_size=%d vbmeta_size=%d", meta.Footer.OriginalImageSize, meta.Footer.VBMetaSize)
	}
	changes = compareField(changes, "footer", footer(old), footer(new))
	changes = compareField(changes, "algorithm", old.Algorithm, new.Algorithm)
	changes = compareField(changes, "rollback_index", fmt.Sprint(old.RollbackIndex), fmt.Sprint(new.RollbackIndex))
	changes = compareField(changes, "flags", fmt.Sprint(old.Flags), fmt.Sprint(new.Flags))
	changes = compareField(changes, "public_key_sha1", old.PublicKeySHA1, new.PublicKeySHA1)
	index := func(meta *avb.VBMeta) map[string]avb.Descriptor {
		result := map[string]avb.Descriptor{}
		for _, descriptor := range meta.Descriptors {
			result[descriptorKey(descriptor)] = descriptor
		}
		return result
	}
	oldIndex, newIndex := index(old), index(new)
	for _, descriptor := range old.Descriptors {
		key := descriptorKey(descriptor)
		other, ok := newIndex[key]
		if !ok {
			changes = append(changes, fieldChange{Field: key, Old: "present", New: "removed"})
			continue
		}
		changes = compareField(changes, key+" image_size", fmt.Sprint(descriptor.ImageSize), fmt.Sprint(other.ImageSize))
		changes = compareField(changes, key+" digest", descriptor.Digest, other.Digest)
		changes = compareField(changes, key+" salt", descriptor.Salt, other.Salt)
		changes = compareField(changes, key+" value", descriptor.Value, other.Value)
		changes = compareField(changes, key+" public_key_sha1", descriptor.PublicKeySHA1, other.PublicKeySHA1)
	}
	for _, descriptor := range new.Descriptors {
		if _, ok := oldIndex[descriptorKey(descriptor)]; !ok {
			changes = append(changes, fieldChange{Field: descriptorKey(descriptor), Old: "absent", New: "added"})
		}
	}
	return changes
}

// buildDiff compares two images section by section, tree by tree and descriptor by descriptor.
func buildDiff(oldPath, newPath string) (*diffReport, error) {
	report := &diffReport{}
	var images [2]*deviceTreeImage
	for index, path := range []string{oldPath, newPath} {
		result, err := detect.File(path)
		if err != nil {
			return nil, err
		}
		summary, err := summarizeFile(path, result.Type)
		if err != nil {
			return nil, err
		}
		if index == 0 {
			report.Old = summary
		} else {
			report.New = summary
		}
		switch result.Type {
		case detect.Boot, detect.VendorBoot, detect.DTB, detect.DTBO:
			if images[index], err = loadDeviceTreeImage(path); err != nil {
				return nil, err
			}
		}
	}
	report.Identical = report.Old.SHA256 == report.New.SHA256
	if old, new := images[0], images[1]; old != nil && new != nil && old.kind == new.kind {
		if old.boot != nil && new.boot != nil {
			diffBoot(report, old, new)
		}
		diffTrees(report, old, new)
	}
	report.AVB = diffAVB(readVBMeta(oldPath), readVBMeta(newPath))
	return report, nil
}

func printDiff(out io.Writer, report *diffReport) error {
	var builder strings.Builder
	for _, side := range []struct {
		name    string
		summary fileSummary
	}{{"old", report.Old}, {"new", report.New}} {
		fmt.Fprintf(&builder, "%s %s type=%s size=%d sha256=%s\n", side.name, side.summary.Path, side.summary.Type, side.summary.Size, side.summary.SHA256)
	}
	if report.Identical {
		builder.WriteString("identical\n")
		_, err := io.WriteString(out, builder.String())
		return err
	}
	if report.Old.Type != report.New.Type {
		fmt.Fprintf(&builder, "type %s -> %s\n", report.Old.Type, report.New.Type)
	}
	if len(report.Sections) > 0 {
		if len(report.Header) == 0 {
			builder.WriteString("header fields same\n")
		}
		for _, change := range report.Header {
			if change.Field == "other bytes" {
				fmt.Fprintf(&builder, "header other bytes differ at offsets %s\n", change.New)
				continue
			}
			fmt.Fprintf(&builder, "header %s: %q -> %q\n", change.Field, change.Old, change.New)
		}
	}
	for _, section := range report.Sections {
		fmt.Fprintf(&builder, "section %s %s", section.Name, section.Status)
		if section.OldSize != section.NewSize {
			fmt.Fprintf(&builder, " size %d -> %d", section.OldSize, section.NewSize)
		}
		builder.WriteString("\n")
	}
	for _, ramdisk := range report.VendorRamdisks {
		fmt.Fprintf(&builder, "vendor_ramdisk %s %s", ramdisk.Name, ramdisk.Status)
		if ramdisk.OldSize != ramdisk.NewSize {
			fmt.Fprintf(&builder, " size %d -> %d", ramdisk.OldSize, ramdisk.NewSize)
		}
		builder.WriteString("\n")
		for _, change := range ramdisk.Fields {
			fmt.Fprintf(&builder, "  %s: %s -> %s\n", change.Field, change.Old, change.New)
		}
	}
	for _, line := range report.BootconfigRemoved {
		fmt.Fprintf(&builder, "bootconfig - %s\n", line)
	}
	for _, line := range report.BootconfigAdded {
		fmt.Fprintf(&builder, "bootconfig + %s\n", line)
	}
	if report.OldTrees > 0 || report.NewTrees > 0 {
		fmt.Fprintf(&builder, "trees %d -> %d\n", report.OldTrees, report.NewTrees)
	}
	for _, tree := range report.Trees {
		model := tree.OldModel
		if model == "" {
			model = tree.NewModel
		}
		fmt.Fprintf(&builder, "tree %02d %s", tree.Index, tree.Status)
		if model != "" {
			fmt.Fprintf(&builder, " model=%q", model)
		}
		builder.WriteString("\n")
		if tree.OldModel != tree.NewModel && tree.OldModel != "" && tree.NewModel != "" {
			fmt.Fprintf(&builder, "  model %q -> %q\n", tree.OldModel, tree.NewModel)
		}
		for _, change := range tree.Fields {
			fmt.Fprintf(&builder, "  %s: %s -> %s\n", change.Field, change.Old, change.New)
		}
		for _, change := range tree.Changes {
			switch change.Kind {
			case fdt.PropertyChanged:
				fmt.Fprintf(&builder, "  ~ %s %s: %s -> %s\n", change.Path, change.Property, formatWithDecimal(change.OldValue), formatWithDecimal(change.NewValue))
			case fdt.PropertyAdded:
				fmt.Fprintf(&builder, "  + %s %s: %s\n", change.Path, change.Property, formatWithDecimal(change.NewValue))
			case fdt.PropertyRemoved:
				fmt.Fprintf(&builder, "  - %s %s: %s\n", change.Path, change.Property, formatWithDecimal(change.OldValue))
			case fdt.NodeAdded:
				fmt.Fprintf(&builder, "  + node %s\n", change.Path)
			case fdt.NodeRemoved:
				fmt.Fprintf(&builder, "  - node %s\n", change.Path)
			}
		}
	}
	if len(report.AVB) == 0 {
		builder.WriteString("avb same\n")
	}
	for _, change := range report.AVB {
		fmt.Fprintf(&builder, "avb %s: %s -> %s\n", change.Field, change.Old, change.New)
	}
	_, err := io.WriteString(out, builder.String())
	return err
}

func newDiffCommand() *cobra.Command {
	var jsonOutput, exitCode bool
	cmd := &cobra.Command{Use: "diff <old> <new>", Short: "Compare two images section by section and tree by tree", Long: "Compare two images and list what differs.\n\nboot and vendor_boot:\n  Header fields are compared one by one, including each section size.\n  Each section is marked same or different.\n  The vendor ramdisk table and bootconfig are compared line by line.\n\nDevice trees (dtb, DTBO and the dtb section of boot images):\n  Trees are paired by index; a change shows the node path, property, old value and new value.\n  equivalent means the bytes differ but the content is the same, usually after a dtc rebuild.\n\nAVB: footer and descriptor changes, such as the image digest.\n\nThe exit status is 0 unless --exit-code is given; then it is 0 when identical, 1 when different and 2 on errors.", Example: "  artb diff vendor_boot.img vendor_boot_patched.img\n  artb diff dtbo.img dtbo_new.img --json\n  artb diff boot.img boot_new.img --exit-code", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Root().SilenceUsage = true
		err := runDiff(cmd, args, jsonOutput)
		exit := (*ExitError)(nil)
		differs := errors.As(err, &exit) && exit.Silent
		switch {
		case differs && !exitCode:
			return nil
		case err != nil && !differs && exitCode:
			return &ExitError{Code: 2, Err: err}
		}
		return err
	}}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Print JSON output")
	cmd.Flags().BoolVar(&exitCode, "exit-code", false, "Exit with 1 when the images differ and 2 on errors")
	return cmd
}

// runDiff prints the report and, when the images differ, returns a silent exit status 1 that only --exit-code keeps.
func runDiff(cmd *cobra.Command, args []string, jsonOutput bool) error {
	var paths [2]string
	for index, arg := range args {
		path, err := filepath.Abs(arg)
		if err != nil {
			return fmt.Errorf("resolve %q: %w", arg, err)
		}
		paths[index] = path
	}
	report, err := buildDiff(paths[0], paths[1])
	if err != nil {
		return err
	}
	if jsonOutput {
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetEscapeHTML(false)
		err = encoder.Encode(report)
	} else {
		err = printDiff(cmd.OutOrStdout(), report)
	}
	if err == nil && !report.Identical {
		return &ExitError{Code: 1, Silent: true}
	}
	return err
}
