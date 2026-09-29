package fdt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Clone deep-copies the tree so it can be edited; cloned values no longer alias the blob and have Offset -1.
func (tree *Tree) Clone() *Tree {
	return &Tree{Header: tree.Header, Root: cloneNode(tree.Root, nil)}
}

func cloneNode(node, parent *Node) *Node {
	copied := &Node{Name: node.Name, Path: node.Path, Parent: parent}
	for _, property := range node.Properties {
		copied.Properties = append(copied.Properties, &Property{Name: property.Name, Value: bytes.Clone(property.Value), Offset: -1})
	}
	for _, child := range node.Children {
		copied.Children = append(copied.Children, cloneNode(child, copied))
	}
	return copied
}

// SetProperty replaces or appends a property value.
func (node *Node) SetProperty(name string, value []byte) {
	if property := node.Property(name); property != nil {
		property.Value, property.Offset = value, -1
		return
	}
	node.Properties = append(node.Properties, &Property{Name: name, Value: value, Offset: -1})
}

func (node *Node) addChild(name string) *Node {
	child := &Node{Name: name, Path: joinPath(node.Path, name), Parent: node}
	node.Children = append(node.Children, child)
	return child
}

func (node *Node) phandle() uint32 {
	for _, name := range []string{"phandle", "linux,phandle"} {
		if property := node.Property(name); property != nil && len(property.Value) == 4 {
			return binary.BigEndian.Uint32(property.Value)
		}
	}
	return 0
}

func (tree *Tree) findPhandle(phandle uint32) *Node {
	var found *Node
	_ = tree.Root.Walk(func(node *Node) error {
		if found == nil && node.phandle() == phandle {
			found = node
		}
		return nil
	})
	return found
}

func maxPhandle(root *Node) uint32 {
	var highest uint32
	_ = root.Walk(func(node *Node) error {
		if phandle := node.phandle(); phandle != 0xffffffff {
			highest = max(highest, phandle)
		}
		return nil
	})
	return highest
}

func addToCell(value []byte, offset int, delta uint32) error {
	if offset < 0 || offset+4 > len(value) {
		return fmt.Errorf("phandle reference at offset %d lies outside a %d-byte value", offset, len(value))
	}
	binary.BigEndian.PutUint32(value[offset:], binary.BigEndian.Uint32(value[offset:])+delta)
	return nil
}

// adjustLocal adds delta to every overlay phandle and to the references __local_fixups__ lists for them.
func adjustLocal(overlay *Node, delta uint32) error {
	err := overlay.Walk(func(node *Node) error {
		for _, name := range []string{"phandle", "linux,phandle"} {
			if property := node.Property(name); property != nil && len(property.Value) == 4 {
				if err := addToCell(property.Value, 0, delta); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	local, err := overlay.Child("__local_fixups__")
	if err != nil {
		return nil
	}
	var walk func(fixups, target *Node) error
	walk = func(fixups, target *Node) error {
		for _, property := range fixups.Properties {
			value := target.Property(property.Name)
			if value == nil {
				return fmt.Errorf("__local_fixups__ names missing property %s %s", target.Path, property.Name)
			}
			cells := property.Cells()
			if cells == nil {
				return fmt.Errorf("__local_fixups__ %s %s is not a list of offsets", fixups.Path, property.Name)
			}
			for _, offset := range cells {
				if err := addToCell(value.Value, int(offset), delta); err != nil {
					return fmt.Errorf("%s %s: %w", target.Path, property.Name, err)
				}
			}
		}
		for _, child := range fixups.Children {
			next := findExact(target, child.Name)
			if next == nil {
				return fmt.Errorf("__local_fixups__ names missing node %s", joinPath(target.Path, child.Name))
			}
			if err := walk(child, next); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(local, overlay)
}

// resolveFixups writes the phandles of base labels into the overlay locations that __fixups__ lists.
func resolveFixups(base *Tree, overlay *Tree) error {
	fixups, err := overlay.Root.Child("__fixups__")
	if err != nil {
		return nil
	}
	symbols, err := base.Root.Child("__symbols__")
	if err != nil {
		return errors.New("the overlay references labels but the base tree has no __symbols__ (build it with dtc -@)")
	}
	for _, fixup := range fixups.Properties {
		symbol := symbols.Property(fixup.Name)
		if symbol == nil {
			return fmt.Errorf("base tree has no label %s", fixup.Name)
		}
		target, err := base.Lookup(strings.TrimRight(string(symbol.Value), "\x00"))
		if err != nil {
			return fmt.Errorf("label %s: %w", fixup.Name, err)
		}
		phandle := target.phandle()
		if phandle == 0 {
			return fmt.Errorf("label %s points at %s, which has no phandle", fixup.Name, target.Path)
		}
		for _, reference := range SplitStrings(fixup.Value) {
			parts := strings.Split(reference, ":")
			if len(parts) != 3 {
				return fmt.Errorf("bad __fixups__ entry %q", reference)
			}
			offset, err := strconv.Atoi(parts[2])
			if err != nil {
				return fmt.Errorf("bad __fixups__ offset in %q", reference)
			}
			node, err := overlay.Lookup(parts[0])
			if err != nil {
				return fmt.Errorf("__fixups__ %q: %w", reference, err)
			}
			property := node.Property(parts[1])
			if property == nil || offset < 0 || offset+4 > len(property.Value) {
				return fmt.Errorf("__fixups__ %q does not point inside a property", reference)
			}
			binary.BigEndian.PutUint32(property.Value[offset:], phandle)
		}
	}
	return nil
}

func mergeNode(target, source *Node) {
	for _, property := range source.Properties {
		target.SetProperty(property.Name, property.Value)
	}
	for _, child := range source.Children {
		existing := findExact(target, child.Name)
		if existing == nil {
			existing = target.addChild(child.Name)
		}
		mergeNode(existing, child)
	}
}

// ApplyOverlay merges an overlay into a copy of base like libufdt's ufdt_overlay_apply, which Qualcomm ABL uses: root properties and __symbols__ stay as in base.
func ApplyOverlay(base, overlay *Tree) (*Tree, error) {
	merged, layer := base.Clone(), overlay.Clone()
	if err := adjustLocal(layer.Root, maxPhandle(merged.Root)); err != nil {
		return nil, err
	}
	if err := resolveFixups(merged, layer); err != nil {
		return nil, err
	}
	for _, fragment := range layer.Root.Children {
		content := findExact(fragment, "__overlay__")
		if content == nil {
			continue
		}
		var target *Node
		if property := fragment.Property("target"); property != nil && len(property.Value) == 4 {
			if target = merged.findPhandle(binary.BigEndian.Uint32(property.Value)); target == nil {
				return nil, fmt.Errorf("%s targets phandle 0x%x, which the base tree lacks", fragment.Path, binary.BigEndian.Uint32(property.Value))
			}
		} else if property := fragment.Property("target-path"); property != nil {
			found, err := merged.Lookup(strings.TrimRight(string(property.Value), "\x00"))
			if err != nil {
				return nil, fmt.Errorf("%s: %w", fragment.Path, err)
			}
			target = found
		} else {
			return nil, fmt.Errorf("%s has __overlay__ but neither target nor target-path", fragment.Path)
		}
		mergeNode(target, content)
	}
	return merged, nil
}

// Encode serializes the tree as a version 17 flattened device tree, keeping reservations from memrsv.
func (tree *Tree) Encode(memrsv []byte) []byte {
	be := binary.BigEndian
	var structure, names bytes.Buffer
	offsets := map[string]int{}
	var write func(node *Node)
	write = func(node *Node) {
		structure.Write(be.AppendUint32(nil, 1))
		structure.WriteString(node.Name)
		structure.WriteByte(0)
		for structure.Len()%4 != 0 {
			structure.WriteByte(0)
		}
		for _, property := range node.Properties {
			offset, ok := offsets[property.Name]
			if !ok {
				offset = names.Len()
				offsets[property.Name] = offset
				names.WriteString(property.Name)
				names.WriteByte(0)
			}
			structure.Write(be.AppendUint32(be.AppendUint32(be.AppendUint32(nil, 3), uint32(len(property.Value))), uint32(offset)))
			structure.Write(property.Value)
			for structure.Len()%4 != 0 {
				structure.WriteByte(0)
			}
		}
		for _, child := range node.Children {
			write(child)
		}
		structure.Write(be.AppendUint32(nil, 2))
	}
	write(tree.Root)
	structure.Write(be.AppendUint32(nil, 9))
	if len(memrsv) == 0 {
		memrsv = make([]byte, 16)
	}
	offMemRsv := (HeaderSize + 7) &^ 7
	offStruct := offMemRsv + len(memrsv)
	offStrings := offStruct + structure.Len()
	total := offStrings + names.Len()
	out := make([]byte, offMemRsv, total)
	for index, value := range []uint32{Magic, uint32(total), uint32(offStruct), uint32(offStrings), uint32(offMemRsv), 17, 16, tree.Header.BootCPUID, uint32(names.Len()), uint32(structure.Len())} {
		be.PutUint32(out[4*index:], value)
	}
	out = append(out, memrsv...)
	out = append(out, structure.Bytes()...)
	return append(out, names.Bytes()...)
}

// MemReserve returns the memory reservation block of blob including its terminating entry.
func MemReserve(blob []byte) []byte {
	header, err := ParseHeader(blob)
	if err != nil {
		return nil
	}
	for position := int(header.OffMemRsv); position+16 <= len(blob); position += 16 {
		if binary.BigEndian.Uint64(blob[position:]) == 0 && binary.BigEndian.Uint64(blob[position+8:]) == 0 {
			return blob[header.OffMemRsv : position+16]
		}
	}
	return nil
}
