package fdt

import "bytes"

// Change is one difference between two device trees; Old and New are dts-formatted values.
type Change struct {
	Kind     string `json:"kind"`
	Path     string `json:"path"`
	Property string `json:"property,omitempty"`
	Old      string `json:"old,omitempty"`
	New      string `json:"new,omitempty"`
	OldValue []byte `json:"-"`
	NewValue []byte `json:"-"`
}

// Change kinds reported by Diff.
const (
	NodeAdded       = "node-added"
	NodeRemoved     = "node-removed"
	PropertyAdded   = "property-added"
	PropertyRemoved = "property-removed"
	PropertyChanged = "property-changed"
)

// Diff lists added and removed nodes and added, removed and changed properties, matching children by name.
func Diff(old, new *Node) []Change {
	var changes []Change
	for _, property := range old.Properties {
		other := new.Property(property.Name)
		switch {
		case other == nil:
			changes = append(changes, Change{Kind: PropertyRemoved, Path: old.Path, Property: property.Name, Old: FormatValue(property.Value), OldValue: property.Value})
		case !bytes.Equal(property.Value, other.Value):
			changes = append(changes, Change{Kind: PropertyChanged, Path: old.Path, Property: property.Name, Old: FormatValue(property.Value), New: FormatValue(other.Value), OldValue: property.Value, NewValue: other.Value})
		}
	}
	for _, property := range new.Properties {
		if old.Property(property.Name) == nil {
			changes = append(changes, Change{Kind: PropertyAdded, Path: new.Path, Property: property.Name, New: FormatValue(property.Value), NewValue: property.Value})
		}
	}
	for _, child := range old.Children {
		other := findExact(new, child.Name)
		if other == nil {
			changes = append(changes, Change{Kind: NodeRemoved, Path: child.Path})
			continue
		}
		changes = append(changes, Diff(child, other)...)
	}
	for _, child := range new.Children {
		if findExact(old, child.Name) == nil {
			changes = append(changes, Change{Kind: NodeAdded, Path: child.Path})
		}
	}
	return changes
}

func findExact(node *Node, name string) *Node {
	for _, child := range node.Children {
		if child.Name == name {
			return child
		}
	}
	return nil
}
