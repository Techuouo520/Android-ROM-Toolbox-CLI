// Package fdt reads flattened device tree headers and splits files that hold several device trees.
package fdt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	Magic      = 0xd00dfeed
	HeaderSize = 40
)

// Header is the fixed big-endian header of a flattened device tree.
type Header struct {
	TotalSize, OffStruct, OffStrings, OffMemRsv, Version, LastCompVersion, BootCPUID, SizeStrings, SizeStruct uint32
}

// ParseHeader validates the header at the start of data; data may extend past the tree.
func ParseHeader(data []byte) (Header, error) {
	if len(data) < HeaderSize {
		return Header{}, errors.New("device tree shorter than its header")
	}
	be := binary.BigEndian
	if be.Uint32(data) != Magic {
		return Header{}, errors.New("missing device tree magic")
	}
	header := Header{TotalSize: be.Uint32(data[4:]), OffStruct: be.Uint32(data[8:]), OffStrings: be.Uint32(data[12:]), OffMemRsv: be.Uint32(data[16:]), Version: be.Uint32(data[20:]), LastCompVersion: be.Uint32(data[24:]), BootCPUID: be.Uint32(data[28:]), SizeStrings: be.Uint32(data[32:]), SizeStruct: be.Uint32(data[36:])}
	if header.TotalSize < HeaderSize || uint64(header.TotalSize) > uint64(len(data)) {
		return Header{}, fmt.Errorf("device tree size %d does not fit the %d available bytes", header.TotalSize, len(data))
	}
	if header.Version < 16 || uint64(header.OffStruct)+uint64(header.SizeStruct) > uint64(header.TotalSize) || uint64(header.OffStrings)+uint64(header.SizeStrings) > uint64(header.TotalSize) {
		return Header{}, fmt.Errorf("unsupported or damaged device tree (version %d)", header.Version)
	}
	return header, nil
}

// Segment is one device tree or the bytes between device trees in a concatenated file.
type Segment struct {
	Blob bool
	Data []byte
}

// Split cuts data into consecutive device trees, keeping any bytes that are not a valid tree as raw segments.
func Split(data []byte) ([]Segment, error) {
	var segments []Segment
	blobs := 0
	magic := binary.BigEndian.AppendUint32(nil, Magic)
	for position := 0; position < len(data); {
		if header, err := ParseHeader(data[position:]); err == nil {
			segments = append(segments, Segment{Blob: true, Data: data[position : position+int(header.TotalSize)]})
			position += int(header.TotalSize)
			blobs++
			continue
		}
		next := len(data)
		for search := position + 1; search < len(data); {
			index := bytes.Index(data[search:], magic)
			if index < 0 {
				break
			}
			if _, err := ParseHeader(data[search+index:]); err == nil {
				next = search + index
				break
			}
			search += index + 1
		}
		segments = append(segments, Segment{Data: data[position:next]})
		position = next
	}
	if blobs == 0 {
		return nil, errors.New("no device tree found")
	}
	return segments, nil
}

// RootNodes lists the names of the nodes directly under the root of blob.
func RootNodes(blob []byte) ([]string, error) {
	header, err := ParseHeader(blob)
	if err != nil {
		return nil, err
	}
	be := binary.BigEndian
	structure := blob[header.OffStruct : header.OffStruct+header.SizeStruct]
	var names []string
	depth := 0
	for position := 0; position+4 <= len(structure); {
		token := be.Uint32(structure[position:])
		position += 4
		switch token {
		case 1:
			end := bytes.IndexByte(structure[position:], 0)
			if end < 0 {
				return nil, errors.New("unterminated node name")
			}
			if depth++; depth == 2 {
				names = append(names, string(structure[position:position+end]))
			}
			position += (end + 4) &^ 3
		case 2:
			depth--
		case 3:
			if position+8 > len(structure) {
				return nil, errors.New("truncated property")
			}
			position += 8 + (int(be.Uint32(structure[position:]))+3)&^3
		case 4:
		case 9:
			return names, nil
		default:
			return nil, fmt.Errorf("unknown structure token %#x", token)
		}
	}
	return nil, errors.New("structure block ends without FDT_END")
}
