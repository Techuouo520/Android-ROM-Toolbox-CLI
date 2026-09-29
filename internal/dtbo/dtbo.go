// Package dtbo reads and writes the Android DTBO partition table that indexes device tree overlays.
package dtbo

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	Magic      = 0xd7b7ab1e
	HeaderSize = 32
	EntrySize  = 32
)

// Compression formats that version 1 tables store in the low four bits of the first custom word.
const (
	NoCompression   = 0
	ZlibCompression = 1
	GzipCompression = 2
)

// Header is the big-endian dt_table_header.
type Header struct {
	TotalSize, HeaderSize, EntrySize, EntryCount, EntriesOffset, PageSize, Version uint32
}

// Entry is a dt_table_entry; in version 1 Custom[0] carries the flags word.
type Entry struct {
	Size, Offset, ID, Rev uint32
	Custom                [4]uint32
}

// Compression returns the compression format of the entry payload.
func (entry Entry) Compression(version uint32) uint32 {
	if version >= 1 {
		return entry.Custom[0] & 0xf
	}
	return NoCompression
}

// Parse reads the table at the start of data and checks that every entry lies inside the table's total size.
func Parse(data []byte) (Header, []Entry, error) {
	if len(data) < HeaderSize {
		return Header{}, nil, errors.New("DTBO image shorter than its header")
	}
	be := binary.BigEndian
	if be.Uint32(data) != Magic {
		return Header{}, nil, errors.New("missing DTBO magic")
	}
	header := Header{TotalSize: be.Uint32(data[4:]), HeaderSize: be.Uint32(data[8:]), EntrySize: be.Uint32(data[12:]), EntryCount: be.Uint32(data[16:]), EntriesOffset: be.Uint32(data[20:]), PageSize: be.Uint32(data[24:]), Version: be.Uint32(data[28:])}
	if uint64(header.TotalSize) > uint64(len(data)) || header.HeaderSize < HeaderSize || header.EntrySize < EntrySize {
		return Header{}, nil, fmt.Errorf("DTBO header sizes are invalid (total %d, header %d, entry %d)", header.TotalSize, header.HeaderSize, header.EntrySize)
	}
	if uint64(header.EntriesOffset)+uint64(header.EntryCount)*uint64(header.EntrySize) > uint64(header.TotalSize) {
		return Header{}, nil, errors.New("DTBO entries lie outside the table")
	}
	entries := make([]Entry, header.EntryCount)
	for index := range entries {
		raw := data[int(header.EntriesOffset)+index*int(header.EntrySize):]
		entry := Entry{Size: be.Uint32(raw), Offset: be.Uint32(raw[4:]), ID: be.Uint32(raw[8:]), Rev: be.Uint32(raw[12:])}
		for word := range entry.Custom {
			entry.Custom[word] = be.Uint32(raw[16+4*word:])
		}
		if uint64(entry.Offset)+uint64(entry.Size) > uint64(header.TotalSize) {
			return Header{}, nil, fmt.Errorf("DTBO entry %d lies outside the table", index)
		}
		entries[index] = entry
	}
	return header, entries, nil
}

// Encode writes the header followed by the entries at header.EntriesOffset; the caller fills TotalSize and offsets.
func Encode(header Header, entries []Entry) []byte {
	be := binary.BigEndian
	out := make([]byte, int(header.EntriesOffset)+len(entries)*int(header.EntrySize))
	for index, value := range []uint32{Magic, header.TotalSize, header.HeaderSize, header.EntrySize, uint32(len(entries)), header.EntriesOffset, header.PageSize, header.Version} {
		be.PutUint32(out[4*index:], value)
	}
	for index, entry := range entries {
		raw := out[int(header.EntriesOffset)+index*int(header.EntrySize):]
		be.PutUint32(raw, entry.Size)
		be.PutUint32(raw[4:], entry.Offset)
		be.PutUint32(raw[8:], entry.ID)
		be.PutUint32(raw[12:], entry.Rev)
		for word, value := range entry.Custom {
			be.PutUint32(raw[16+4*word:], value)
		}
	}
	return out
}

// Decompress returns the device tree stored in an entry payload.
func Decompress(payload []byte, compression uint32) ([]byte, error) {
	var reader io.ReadCloser
	var err error
	switch compression {
	case NoCompression:
		return payload, nil
	case ZlibCompression:
		reader, err = zlib.NewReader(bytes.NewReader(payload))
	case GzipCompression:
		reader, err = gzip.NewReader(bytes.NewReader(payload))
	default:
		return nil, fmt.Errorf("unsupported DTBO compression %d", compression)
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// Compress encodes a device tree for an entry with the given compression.
func Compress(tree []byte, compression uint32) ([]byte, error) {
	var buffer bytes.Buffer
	var writer io.WriteCloser
	switch compression {
	case NoCompression:
		return tree, nil
	case ZlibCompression:
		writer = zlib.NewWriter(&buffer)
	case GzipCompression:
		writer = gzip.NewWriter(&buffer)
	default:
		return nil, fmt.Errorf("unsupported DTBO compression %d", compression)
	}
	if _, err := writer.Write(tree); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
