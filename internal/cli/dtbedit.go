package cli

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"artb/internal/avb"
	"artb/internal/fdt"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

// editRecord is a finished edit kept for the report.
type editRecord struct {
	Tree     int    `json:"tree"`
	Path     string `json:"path"`
	Property string `json:"property"`
	Old      []byte `json:"-"`
	New      []byte `json:"-"`
}

// formatWithDecimal renders a value and, for cells, their decimal form.
func formatWithDecimal(value []byte) string {
	text := fdt.FormatValue(value)
	if text == "" {
		text = "<empty>"
	}
	if decimal := fdt.FormatDecimal(value); decimal != "" {
		text += " (" + decimal + ")"
	}
	return text
}

func parseTreeList(text string) ([]int, bool, error) {
	if text == "" {
		return nil, false, nil
	}
	if text == "all" {
		return nil, true, nil
	}
	var indexes []int
	for _, field := range strings.Split(text, ",") {
		index, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil {
			return nil, false, fmt.Errorf("tree %q is not a number, a comma-separated list or all", text)
		}
		indexes = append(indexes, index)
	}
	return indexes, false, nil
}

// locateProperty finds node and property in tree, reporting which one is missing.
func locateProperty(tree *deviceTree, path, name string) (*fdt.Node, *fdt.Property, error) {
	node, err := tree.Tree.Lookup(path)
	if err != nil {
		return nil, nil, fmt.Errorf("tree %d: %w", tree.Index, err)
	}
	property := node.Property(name)
	if property == nil {
		return nil, nil, fmt.Errorf("tree %d: %s has no property %s", tree.Index, node.Path, name)
	}
	return node, property, nil
}

// editOptions are the output settings shared by dtb set and dtb patch.
type editOptions struct {
	output, keyPath, vbmetaPath string
	force, quiet                bool
}

func (options *editOptions) register(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&options.output, "output", "o", "", "Set output image path (default: <image>_patched beside the input)")
	cmd.Flags().StringVar(&options.keyPath, "avb-key", "", "Re-sign a signed AVB footer with this RSA private key (PEM)")
	cmd.Flags().StringVar(&options.vbmetaPath, "vbmeta", "", "Check that this vbmeta image records the new image digest")
	cmd.Flags().BoolVar(&options.force, "force", false, "Replace the output file if it already exists")
	cmd.Flags().BoolVarP(&options.quiet, "quiet", "q", false, "Suppress success output")
}

// skippedTree is a tree left out of an all or --skip-missing edit, kept for the report.
type skippedTree struct {
	Tree   int
	Reason string
}

// finishEdits writes the edited image and prints what changed and which trees were left out.
func finishEdits(cmd *cobra.Command, image *deviceTreeImage, records []editRecord, skipped []skippedTree, options editOptions, started time.Time) error {
	key, err := loadKey(options.keyPath)
	if err != nil {
		return err
	}
	output := options.output
	if output == "" {
		output = patchedName(image.path)
	}
	if output, err = filepath.Abs(output); err != nil {
		return err
	}
	footer, err := image.write(output, key, options.force)
	if err != nil {
		return err
	}
	if footer != nil && footer.StaleSignature {
		fmt.Fprintf(cmd.ErrOrStderr(), "%s: the AVB footer signature no longer matches; pass --avb-key to re-sign it\n", output)
	}
	out := cmd.OutOrStdout()
	if options.quiet {
		out = io.Discard
	}
	if err = checkVBMeta(out, cmd.ErrOrStderr(), options.vbmetaPath, output); err != nil {
		return err
	}
	if options.quiet {
		return nil
	}
	fmt.Fprintln(out, output)
	for _, record := range records {
		state := "changed"
		if bytes.Equal(record.Old, record.New) {
			state = "unchanged"
		}
		fmt.Fprintf(out, "tree %02d %s %s %s: %s -> %s\n", record.Tree, record.Path, record.Property, state, formatWithDecimal(record.Old), formatWithDecimal(record.New))
	}
	for _, skip := range skipped {
		fmt.Fprintf(out, "tree %02d skipped: %s\n", skip.Tree, skip.Reason)
	}
	if footer != nil {
		if err = printHashDescriptors(out, output); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(out, "elapsed %.3fs\n", time.Since(started).Seconds())
	return err
}

func printHashDescriptors(out io.Writer, path string) error {
	meta, err := avb.Read(path)
	if err != nil {
		return err
	}
	for _, descriptor := range meta.Descriptors {
		if descriptor.Kind == "hash" {
			fmt.Fprintf(out, "avb %s image_size=%d digest=%s\n", descriptor.Partition, descriptor.ImageSize, descriptor.Digest)
		}
	}
	return nil
}

func loadKey(path string) (*rsa.PrivateKey, error) {
	if path == "" {
		return nil, nil
	}
	return avb.LoadKey(path)
}

func newDTBSetCommand() *cobra.Command {
	var options editOptions
	var trees string
	var skipMissing bool
	cmd := &cobra.Command{Use: "set <image> <node> <property> <value>", Short: "Change one device tree property in place without dtc", Long: "Change one device tree property in place, without dtc.\n\nOnly the bytes of the value are replaced.\nThe strings table, the other trees and everything else stay as they are, so the new value must have the old length.\n\n<node> is an absolute path or &label/sub/path.\n<value> uses dts syntax: <0x1 0x2>, \"text\", [01 02] or /bits/ 64 <...>.\nA bare number such as 615000000 is a 32-bit cell.\n\nWhen the image holds several trees, pick them with --tree (an index, a list or all).\nEvery selected tree must have the property; --skip-missing leaves the others out and lists them.\n\nThe result goes to a new file (default <image>_patched); an existing file needs --force.\nThe v0-v2 boot id and the AVB hash footer are recomputed, and the input is never modified.", Example: "  artb dtb set vendor_boot.img /soc/qcom,kgsl-3d0@3d00000/qcom,gpu-pwrlevel-bins/qcom,gpu-pwrlevels-1/qcom,gpu-pwrlevel@0 qcom,gpu-freq 0x24a827c0 --tree 2\n  artb dtb set dtb.img / model '\"Custom board\"' -o dtb_new.img", Args: cobra.ExactArgs(4), RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Root().SilenceUsage = true
		started := time.Now()
		path, err := filepath.Abs(args[0])
		if err != nil {
			return err
		}
		value, err := fdt.ParseValue(args[3])
		if err != nil {
			return err
		}
		image, err := loadDeviceTreeImage(path)
		if err != nil {
			return err
		}
		indexes, all, err := parseTreeList(trees)
		if err != nil {
			return err
		}
		if !all && len(indexes) == 0 && len(image.trees) > 1 {
			return fmt.Errorf("%s holds %d device trees; pass --tree with an index, a comma-separated list or all", path, len(image.trees))
		}
		selected, err := image.selectTrees(indexes)
		if err != nil {
			return err
		}
		var edits []treeEdit
		var records []editRecord
		var skipped []skippedTree
		for _, tree := range selected {
			node, property, err := locateProperty(tree, args[1], args[2])
			if err != nil {
				if !skipMissing {
					return fmt.Errorf("%w (pass --skip-missing to leave such trees out)", err)
				}
				skipped = append(skipped, skippedTree{Tree: tree.Index, Reason: err.Error()})
				continue
			}
			edits = append(edits, treeEdit{tree: tree, node: node, property: property, value: value})
			records = append(records, editRecord{Tree: tree.Index, Path: node.Path, Property: property.Name, Old: bytes.Clone(property.Value), New: value})
		}
		if len(edits) == 0 {
			return fmt.Errorf("no selected device tree in %s has %s %s", path, args[1], args[2])
		}
		if err = image.apply(edits); err != nil {
			return err
		}
		return finishEdits(cmd, image, records, skipped, options, started)
	}}
	cmd.Flags().StringVar(&trees, "tree", "", "Tree index, comma-separated indexes or all (default: the only tree)")
	cmd.Flags().BoolVar(&skipMissing, "skip-missing", false, "Leave out selected trees that lack the node or property instead of failing")
	options.register(cmd)
	return cmd
}

// patchRecipe is a reusable list of property edits guarded by the values they expect to replace.
type patchRecipe struct {
	Description string        `yaml:"description"`
	Patches     []recipePatch `yaml:"patches"`
}

// recipePatch is one guarded edit; SkipMissing lets selected trees without the node or property be left out and reported.
type recipePatch struct {
	Tree        treeSelector `yaml:"tree"`
	Model       string       `yaml:"model"`
	Path        string       `yaml:"path"`
	Property    string       `yaml:"property"`
	Old         *recipeValue `yaml:"old"`
	New         *recipeValue `yaml:"new"`
	SkipMissing bool         `yaml:"skip_missing"`
}

// treeSelector accepts an index, a list of indexes or all.
type treeSelector struct {
	set     bool
	all     bool
	indexes []int
}

func (selector *treeSelector) UnmarshalYAML(node *yaml.Node) error {
	selector.set = true
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Value == "all" {
			selector.all = true
			return nil
		}
		index, err := strconv.Atoi(node.Value)
		if err != nil {
			return fmt.Errorf("line %d: tree %q is not an index or all", node.Line, node.Value)
		}
		selector.indexes = []int{index}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			index, err := strconv.Atoi(item.Value)
			if err != nil || item.Kind != yaml.ScalarNode {
				return fmt.Errorf("line %d: tree list entry %q is not an index", item.Line, item.Value)
			}
			selector.indexes = append(selector.indexes, index)
		}
	default:
		return fmt.Errorf("line %d: tree must be an index, a list or all", node.Line)
	}
	return nil
}

// recipeValue keeps the scalar text so bare numbers are not reinterpreted by YAML.
type recipeValue struct {
	text string
	line int
}

func (value *recipeValue) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: quote values that use [ ] or commas, for example '[01 02]'", node.Line)
	}
	value.text, value.line = node.Value, node.Line
	return nil
}

func readRecipe(path string) (*patchRecipe, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	recipe := &patchRecipe{}
	if err = decoder.Decode(recipe); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(recipe.Patches) == 0 {
		return nil, fmt.Errorf("%s has no patches", path)
	}
	for index, patch := range recipe.Patches {
		if !patch.Tree.set || patch.Path == "" || patch.Property == "" || patch.Old == nil || patch.New == nil {
			return nil, fmt.Errorf("%s patch %d needs tree, path, property, old and new", path, index+1)
		}
	}
	return recipe, nil
}

// applyRecipe checks every patch against the current bytes and applies them in order; any mismatch aborts the whole recipe.
func applyRecipe(image *deviceTreeImage, recipe *patchRecipe) ([]editRecord, []skippedTree, error) {
	var records []editRecord
	var skipped []skippedTree
	var problems []error
	for number, patch := range recipe.Patches {
		label := fmt.Sprintf("patch %d (%s %s)", number+1, patch.Path, patch.Property)
		oldValue, err := fdt.ParseValue(patch.Old.text)
		if err != nil {
			problems = append(problems, fmt.Errorf("%s old: %w", label, err))
			continue
		}
		newValue, err := fdt.ParseValue(patch.New.text)
		if err != nil {
			problems = append(problems, fmt.Errorf("%s new: %w", label, err))
			continue
		}
		selected, err := image.selectTrees(patch.Tree.indexes)
		if err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", label, err))
			continue
		}
		matched, before := 0, len(problems)
		for _, tree := range selected {
			if patch.Model != "" {
				if model := tree.Tree.Summarize().Model; model != patch.Model {
					if !patch.Tree.all {
						problems = append(problems, fmt.Errorf("%s: tree %d model is %q, recipe expects %q", label, tree.Index, model, patch.Model))
					} else {
						skipped = append(skipped, skippedTree{Tree: tree.Index, Reason: fmt.Sprintf("patch %d: model %q is not %q", number+1, model, patch.Model)})
					}
					continue
				}
			}
			node, property, err := locateProperty(tree, patch.Path, patch.Property)
			if err != nil {
				if patch.SkipMissing {
					skipped = append(skipped, skippedTree{Tree: tree.Index, Reason: fmt.Sprintf("patch %d: %v", number+1, err)})
				} else {
					problems = append(problems, fmt.Errorf("%s: %w (set skip_missing: true to leave such trees out)", label, err))
				}
				continue
			}
			matched++
			if !bytes.Equal(property.Value, oldValue) {
				problems = append(problems, fmt.Errorf("%s: tree %d holds %s, recipe expects %s", label, tree.Index, formatWithDecimal(property.Value), formatWithDecimal(oldValue)))
				continue
			}
			edit := treeEdit{tree: tree, node: node, property: property, value: newValue}
			if err = edit.check(); err != nil {
				problems = append(problems, fmt.Errorf("%s: %w", label, err))
				continue
			}
			records = append(records, editRecord{Tree: tree.Index, Path: node.Path, Property: property.Name, Old: bytes.Clone(property.Value), New: newValue})
			if len(problems) == 0 {
				if err = image.apply([]treeEdit{edit}); err != nil {
					problems = append(problems, err)
				}
			}
		}
		if matched == 0 && len(problems) == before {
			problems = append(problems, fmt.Errorf("%s: no selected tree has this node and property", label))
		}
	}
	if len(problems) > 0 {
		return nil, nil, fmt.Errorf("recipe not applied, nothing was written:\n%w", errors.Join(problems...))
	}
	return records, skipped, nil
}

func newDTBPatchCommand() *cobra.Command {
	var options editOptions
	var recipePath string
	cmd := &cobra.Command{Use: "patch <image> --recipe <recipe.yaml>", Short: "Apply a reusable recipe of guarded in-place property edits", Long: "Apply a YAML recipe of property edits, for example to redo a change on the stock image of a later update.\n\nEach patch has:\n  tree          tree index, list or all\n  path          node path, absolute or &label/...\n  property      property name\n  old           value the image must hold\n  new           new value\n  model         optional; pins the tree model, or picks trees when tree is all\n  skip_missing  optional; true leaves out trees without the node\n\nIf any old value does not match, nothing is written.\nEdits work like artb dtb set: in place and with the same length.\nThe result goes to a new file (default <image>_patched); an existing file needs --force.", Example: "  artb dtb patch vendor_boot.img --recipe gpu.yaml\n  artb dtb patch vendor_boot.img --recipe gpu.yaml -o vendor_boot_gpu.img\n\n  # gpu.yaml\n  patches:\n    - tree: 2\n      model: Qualcomm Technologies, Inc. Kalama v2 SoC\n      path: /soc/qcom,kgsl-3d0@3d00000/qcom,gpu-pwrlevel-bins/qcom,gpu-pwrlevels-1/qcom,gpu-pwrlevel@0\n      property: qcom,gpu-freq\n      old: <0x2887fa00>\n      new: <0x24a827c0>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Root().SilenceUsage = true
		started := time.Now()
		if recipePath == "" {
			return errors.New("pass --recipe with a YAML recipe")
		}
		path, err := filepath.Abs(args[0])
		if err != nil {
			return err
		}
		recipe, err := readRecipe(recipePath)
		if err != nil {
			return err
		}
		image, err := loadDeviceTreeImage(path)
		if err != nil {
			return err
		}
		records, skipped, err := applyRecipe(image, recipe)
		if err != nil {
			return err
		}
		return finishEdits(cmd, image, records, skipped, options, started)
	}}
	cmd.Flags().StringVar(&recipePath, "recipe", "", "YAML recipe of guarded property edits")
	options.register(cmd)
	return cmd
}
