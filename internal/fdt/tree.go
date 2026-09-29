package fdt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Property is a device tree property; Offset locates Value inside the blob it was parsed from.
type Property struct {
	Name   string
	Value  []byte
	Offset int
}

// Node is a device tree node with its properties and children in blob order.
type Node struct {
	Name       string
	Path       string
	Parent     *Node
	Properties []*Property
	Children   []*Node
}

// Tree is a parsed flattened device tree.
type Tree struct {
	Header Header
	Root   *Node
}

// Parse reads the whole structure block of blob.
func Parse(blob []byte) (*Tree, error) {
	header, err := ParseHeader(blob)
	if err != nil {
		return nil, err
	}
	be := binary.BigEndian
	start, end := int(header.OffStruct), int(header.OffStruct+header.SizeStruct)
	names := blob[header.OffStrings : header.OffStrings+header.SizeStrings]
	tree := &Tree{Header: header}
	var current *Node
	for position := start; position+4 <= end; {
		token := be.Uint32(blob[position:])
		position += 4
		switch token {
		case 1:
			length := bytes.IndexByte(blob[position:end], 0)
			if length < 0 {
				return nil, errors.New("unterminated node name")
			}
			node := &Node{Name: string(blob[position : position+length]), Parent: current}
			if current == nil {
				if tree.Root != nil {
					return nil, errors.New("more than one root node")
				}
				node.Path, tree.Root = "/", node
			} else {
				node.Path = joinPath(current.Path, node.Name)
				current.Children = append(current.Children, node)
			}
			current = node
			position += (length + 4) &^ 3
		case 2:
			if current == nil {
				return nil, errors.New("unbalanced FDT_END_NODE")
			}
			current = current.Parent
		case 3:
			if current == nil || position+8 > end {
				return nil, errors.New("property outside a node or truncated")
			}
			size, nameOffset := int(be.Uint32(blob[position:])), int(be.Uint32(blob[position+4:]))
			position += 8
			if position+size > end || nameOffset >= len(names) {
				return nil, errors.New("property value or name out of range")
			}
			nameEnd := bytes.IndexByte(names[nameOffset:], 0)
			if nameEnd < 0 {
				return nil, errors.New("unterminated property name")
			}
			current.Properties = append(current.Properties, &Property{Name: string(names[nameOffset : nameOffset+nameEnd]), Value: blob[position : position+size], Offset: position})
			position += (size + 3) &^ 3
		case 4:
		case 9:
			if current != nil || tree.Root == nil {
				return nil, errors.New("structure block ends inside a node")
			}
			return tree, nil
		default:
			return nil, fmt.Errorf("unknown structure token %#x", token)
		}
	}
	return nil, errors.New("structure block ends without FDT_END")
}

func joinPath(parent, name string) string {
	if parent == "/" {
		return "/" + name
	}
	return parent + "/" + name
}

// Property returns the named property of node, or nil.
func (node *Node) Property(name string) *Property {
	for _, property := range node.Properties {
		if property.Name == name {
			return property
		}
	}
	return nil
}

// Child finds a direct child by full name, or by the name before '@' when that is unambiguous, as libfdt does.
func (node *Node) Child(name string) (*Node, error) {
	var match *Node
	for _, child := range node.Children {
		if child.Name == name {
			return child, nil
		}
		if !strings.Contains(name, "@") && strings.HasPrefix(child.Name, name+"@") {
			if match != nil {
				return nil, fmt.Errorf("%s matches both %s and %s", joinPath(node.Path, name), match.Path, child.Path)
			}
			match = child
		}
	}
	if match == nil {
		return nil, fmt.Errorf("node %s not found", joinPath(node.Path, name))
	}
	return match, nil
}

// Lookup resolves an absolute path, or &label[/sub/path] through __symbols__.
func (tree *Tree) Lookup(path string) (*Node, error) {
	node := tree.Root
	if strings.HasPrefix(path, "&") {
		label, rest, _ := strings.Cut(path[1:], "/")
		symbols, err := node.Child("__symbols__")
		if err != nil {
			return nil, fmt.Errorf("label &%s needs __symbols__: %w", label, err)
		}
		target := symbols.Property(label)
		if target == nil || len(target.Value) == 0 {
			return nil, fmt.Errorf("label &%s not found in __symbols__", label)
		}
		if node, err = tree.Lookup(strings.TrimRight(string(target.Value), "\x00")); err != nil {
			return nil, err
		}
		path = rest
	} else if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("node path %q must start with / or &label", path)
	}
	for _, name := range strings.Split(path, "/") {
		if name == "" {
			continue
		}
		child, err := node.Child(name)
		if err != nil {
			return nil, err
		}
		node = child
	}
	return node, nil
}

// Walk visits node and its descendants depth first in blob order.
func (node *Node) Walk(visit func(*Node) error) error {
	if err := visit(node); err != nil {
		return err
	}
	for _, child := range node.Children {
		if err := child.Walk(visit); err != nil {
			return err
		}
	}
	return nil
}

// Cells returns the value as big-endian 32-bit cells, or nil when its length is not a multiple of four.
func (property *Property) Cells() []uint32 {
	if len(property.Value)%4 != 0 {
		return nil
	}
	cells := make([]uint32, len(property.Value)/4)
	for index := range cells {
		cells[index] = binary.BigEndian.Uint32(property.Value[4*index:])
	}
	return cells
}

// Summary holds the identification properties bootloaders use to pick a device tree.
type Summary struct {
	Model      string   `json:"model,omitempty"`
	Compatible []string `json:"compatible,omitempty"`
	MsmID      []uint32 `json:"msm_id,omitempty"`
	BoardID    []uint32 `json:"board_id,omitempty"`
	PmicID     []uint32 `json:"pmic_id,omitempty"`
}

// Summarize reads model, compatible and the Qualcomm id properties of the root node.
func (tree *Tree) Summarize() Summary {
	root, summary := tree.Root, Summary{}
	if property := root.Property("model"); property != nil {
		summary.Model = strings.TrimRight(string(property.Value), "\x00")
	}
	if property := root.Property("compatible"); property != nil {
		summary.Compatible = SplitStrings(property.Value)
	}
	for name, target := range map[string]*[]uint32{"qcom,msm-id": &summary.MsmID, "qcom,board-id": &summary.BoardID, "qcom,pmic-id": &summary.PmicID} {
		if property := root.Property(name); property != nil {
			*target = property.Cells()
		}
	}
	return summary
}

// SplitStrings splits a NUL-separated string list.
func SplitStrings(value []byte) []string {
	trimmed := strings.TrimRight(string(value), "\x00")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\x00")
}
