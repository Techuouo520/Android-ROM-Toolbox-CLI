package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"text/tabwriter"

	"artb/internal/fdt"

	"github.com/spf13/cobra"
)

type queryRow struct {
	Tree     int    `json:"tree"`
	Node     string `json:"node"`
	Property string `json:"property"`
	Value    string `json:"value"`
	Decimal  string `json:"decimal,omitempty"`
}

// queryNodes returns the nodes under path (or the root) that match compatible, including descendants when recursive.
func queryNodes(tree *fdt.Tree, path, compatible string, recursive bool) ([]*fdt.Node, error) {
	start := tree.Root
	if path != "" {
		node, err := tree.Lookup(path)
		if err != nil {
			return nil, err
		}
		start = node
	}
	matches := []*fdt.Node{start}
	if compatible != "" {
		matches = nil
		_ = start.Walk(func(node *fdt.Node) error {
			if property := node.Property("compatible"); property != nil && slices.Contains(fdt.SplitStrings(property.Value), compatible) {
				matches = append(matches, node)
			}
			return nil
		})
	}
	if !recursive {
		return matches, nil
	}
	var nodes []*fdt.Node
	seen := map[*fdt.Node]bool{}
	for _, match := range matches {
		_ = match.Walk(func(node *fdt.Node) error {
			if !seen[node] {
				seen[node] = true
				nodes = append(nodes, node)
			}
			return nil
		})
	}
	return nodes, nil
}

func newDTBQueryCommand() *cobra.Command {
	var path, compatible, trees string
	var names []string
	var recursive, jsonOutput bool
	cmd := &cobra.Command{Use: "query <image>", Short: "List device tree properties by node path or compatible as a table", Long: "List device tree properties as a table; cell values also show their decimal form.\n\nChoosing nodes:\n  --path        absolute path or &label/...\n  --compatible  nodes whose compatible list has this string; with --path, only below that node\n  -r            also every node underneath\n\n--property keeps only the named property and can be repeated; names may contain commas.\nAll trees are searched and trees without the node are skipped; --tree picks some.", Example: "  artb dtb query vendor_boot.img --path /soc/qcom,kgsl-3d0@3d00000/qcom,gpu-pwrlevel-bins -r --property qcom,gpu-freq\n  artb dtb query vendor_boot.img --compatible qcom,kgsl-3d0 --property qcom,initial-pwrlevel --tree 2,6", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Root().SilenceUsage = true
		imagePath, err := filepath.Abs(args[0])
		if err != nil {
			return err
		}
		image, err := loadDeviceTreeImage(imagePath)
		if err != nil {
			return err
		}
		indexes, _, err := parseTreeList(trees)
		if err != nil {
			return err
		}
		selected, err := image.selectTrees(indexes)
		if err != nil {
			return err
		}
		var rows []queryRow
		var failures []error
		for _, tree := range selected {
			nodes, err := queryNodes(tree.Tree, path, compatible, recursive)
			if err != nil {
				failures = append(failures, fmt.Errorf("tree %d: %w", tree.Index, err))
				continue
			}
			for _, node := range nodes {
				for _, property := range node.Properties {
					if len(names) > 0 && !slices.Contains(names, property.Name) {
						continue
					}
					rows = append(rows, queryRow{Tree: tree.Index, Node: node.Path, Property: property.Name, Value: fdt.FormatValue(property.Value), Decimal: fdt.FormatDecimal(property.Value)})
				}
			}
		}
		if len(rows) == 0 {
			if len(failures) > 0 {
				return errors.Join(failures...)
			}
			return errors.New("no property matches the query")
		}
		if jsonOutput {
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetEscapeHTML(false)
			return encoder.Encode(rows)
		}
		writer := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "TREE\tNODE\tPROPERTY\tVALUE\tDECIMAL")
		for _, row := range rows {
			fmt.Fprintf(writer, "%02d\t%s\t%s\t%s\t%s\n", row.Tree, row.Node, row.Property, row.Value, row.Decimal)
		}
		return writer.Flush()
	}}
	cmd.Flags().StringVar(&path, "path", "", "Node path, absolute or &label/sub/path")
	cmd.Flags().StringVar(&compatible, "compatible", "", "Only nodes whose compatible list contains this string")
	cmd.Flags().StringArrayVar(&names, "property", nil, "Only this property; repeat for more")
	cmd.Flags().StringVar(&trees, "tree", "", "Tree index or comma-separated indexes (default: all)")
	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "Include every node below the selected ones")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Print JSON output")
	return cmd
}
