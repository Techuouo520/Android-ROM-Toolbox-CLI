// Package bootimg parses the headers of Android boot, init_boot, recovery and vendor_boot images and locates their sections.
package bootimg

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

const (
	BootMagic   = "ANDROID!"
	VendorMagic = "VNDRBOOT"
	// The v0-v2 id field holds a SHA-1 or SHA-256 over the sections, padded to 32 bytes.
	idOffset = 576
	idSize   = 32
)

// Section is a contiguous region of the image file.
type Section struct {
	Name   string `json:"name"`
	Offset int64  `json:"offset"`
	Size   int64  `json:"size"`
}

// VendorRamdisk is one entry of the vendor ramdisk table of a v4 vendor_boot image; Offset is absolute in the file.
type VendorRamdisk struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Offset  int64    `json:"offset"`
	Size    int64    `json:"size"`
	BoardID []uint32 `json:"board_id"`
}

// Image describes a boot or vendor_boot header; addresses are only meaningful for the versions that store them.
type Image struct {
	Vendor         bool            `json:"vendor"`
	HeaderVersion  uint32          `json:"header_version"`
	HeaderSize     uint32          `json:"header_size"`
	PageSize       uint32          `json:"page_size"`
	OSVersion      string          `json:"os_version,omitempty"`
	OSPatchLevel   string          `json:"os_patch_level,omitempty"`
	Name           string          `json:"name,omitempty"`
	Cmdline        string          `json:"cmdline"`
	ExtraCmdline   string          `json:"extra_cmdline,omitempty"`
	KernelAddr     uint32          `json:"kernel_addr,omitempty"`
	RamdiskAddr    uint32          `json:"ramdisk_addr,omitempty"`
	SecondAddr     uint32          `json:"second_addr,omitempty"`
	TagsAddr       uint32          `json:"tags_addr,omitempty"`
	DTBAddr        uint64          `json:"dtb_addr,omitempty"`
	ID             string          `json:"id,omitempty"`
	Sections       []Section       `json:"sections"`
	VendorRamdisks []VendorRamdisk `json:"vendor_ramdisks,omitempty"`
	Bootconfig     string          `json:"bootconfig,omitempty"`
	End            int64           `json:"end"`
}

// Section returns the named section when the image has it.
func (image *Image) Section(name string) (Section, bool) {
	for _, section := range image.Sections {
		if section.Name == name {
			return section, true
		}
	}
	return Section{}, false
}

func cString(raw []byte) string {
	if index := bytes.IndexByte(raw, 0); index >= 0 {
		raw = raw[:index]
	}
	return string(raw)
}

func align(value, page int64) int64 { return (value + page - 1) / page * page }

// decodeOSVersion splits the packed os_version into the Android release and the security patch month.
func decodeOSVersion(packed uint32) (string, string) {
	if packed == 0 {
		return "", ""
	}
	version, level := packed>>11, packed&0x7ff
	release := fmt.Sprintf("%d.%d.%d", version>>14, (version>>7)&0x7f, version&0x7f)
	patch := ""
	if level != 0 {
		patch = fmt.Sprintf("%04d-%02d", 2000+(level>>4), level&0xf)
	}
	return release, patch
}

var ramdiskTypes = []string{"none", "platform", "recovery", "dlkm"}

// Parse reads the header at the start of data and checks that every section lies inside data.
func Parse(data []byte) (*Image, error) {
	switch {
	case len(data) >= 8 && string(data[:8]) == BootMagic:
		return parseBoot(data)
	case len(data) >= 8 && string(data[:8]) == VendorMagic:
		return parseVendor(data)
	}
	return nil, errors.New("not an Android boot or vendor_boot image")
}

func (image *Image) layout(data []byte, page int64, offset int64, names []string, sizes []int64) error {
	for index, name := range names {
		size := sizes[index]
		if offset+size > int64(len(data)) || size < 0 {
			return fmt.Errorf("%s section (%d bytes at %d) extends past the %d-byte file", name, size, offset, len(data))
		}
		image.Sections = append(image.Sections, Section{Name: name, Offset: offset, Size: size})
		offset = align(offset+size, page)
	}
	image.End = offset
	return nil
}

func parseBoot(data []byte) (*Image, error) {
	le := binary.LittleEndian
	if len(data) < 1660 {
		return nil, errors.New("boot image shorter than its header")
	}
	image := &Image{HeaderVersion: le.Uint32(data[40:])}
	if image.HeaderVersion >= 3 {
		image.PageSize, image.HeaderSize = 4096, le.Uint32(data[20:])
		image.OSVersion, image.OSPatchLevel = decodeOSVersion(le.Uint32(data[16:]))
		image.Cmdline = cString(data[44 : 44+1536])
		names, sizes := []string{"header", "kernel", "ramdisk"}, []int64{int64(image.HeaderSize), int64(le.Uint32(data[8:])), int64(le.Uint32(data[12:]))}
		if image.HeaderVersion >= 4 {
			names, sizes = append(names, "signature"), append(sizes, int64(le.Uint32(data[1580:])))
		}
		return image, image.layout(data, 4096, 0, names, sizes)
	}
	image.PageSize = le.Uint32(data[36:])
	if image.PageSize == 0 || image.PageSize&(image.PageSize-1) != 0 {
		return nil, fmt.Errorf("boot image page size %d is not a power of two", image.PageSize)
	}
	image.KernelAddr, image.RamdiskAddr, image.SecondAddr, image.TagsAddr = le.Uint32(data[12:]), le.Uint32(data[20:]), le.Uint32(data[28:]), le.Uint32(data[32:])
	image.OSVersion, image.OSPatchLevel = decodeOSVersion(le.Uint32(data[44:]))
	image.Name, image.Cmdline, image.ExtraCmdline = cString(data[48:64]), cString(data[64:576]), cString(data[608:1632])
	image.ID = fmt.Sprintf("%x", data[idOffset:idOffset+idSize])
	image.HeaderSize = 1632
	names, sizes := []string{"header", "kernel", "ramdisk", "second"}, []int64{0, int64(le.Uint32(data[8:])), int64(le.Uint32(data[16:])), int64(le.Uint32(data[24:]))}
	if image.HeaderVersion >= 1 {
		image.HeaderSize = le.Uint32(data[1644:])
		names, sizes = append(names, "recovery_dtbo"), append(sizes, int64(le.Uint32(data[1632:])))
	}
	if image.HeaderVersion >= 2 {
		image.DTBAddr = le.Uint64(data[1652:])
		names, sizes = append(names, "dtb"), append(sizes, int64(le.Uint32(data[1648:])))
	}
	sizes[0] = int64(image.HeaderSize)
	return image, image.layout(data, int64(image.PageSize), 0, names, sizes)
}

func parseVendor(data []byte) (*Image, error) {
	le := binary.LittleEndian
	if len(data) < 2128 {
		return nil, errors.New("vendor_boot image shorter than its header")
	}
	image := &Image{Vendor: true, HeaderVersion: le.Uint32(data[8:]), PageSize: le.Uint32(data[12:])}
	if image.PageSize == 0 || image.PageSize&(image.PageSize-1) != 0 {
		return nil, fmt.Errorf("vendor_boot page size %d is not a power of two", image.PageSize)
	}
	image.KernelAddr, image.RamdiskAddr = le.Uint32(data[16:]), le.Uint32(data[20:])
	image.Cmdline, image.TagsAddr, image.Name = cString(data[28:2076]), le.Uint32(data[2076:]), cString(data[2080:2096])
	image.HeaderSize, image.DTBAddr = le.Uint32(data[2096:]), le.Uint64(data[2104:])
	page := int64(image.PageSize)
	names, sizes := []string{"header", "vendor_ramdisk", "dtb"}, []int64{int64(image.HeaderSize), int64(le.Uint32(data[24:])), int64(le.Uint32(data[2100:]))}
	var tableEntries, entrySize uint32
	if image.HeaderVersion >= 4 {
		tableEntries, entrySize = le.Uint32(data[2116:]), le.Uint32(data[2120:])
		names = append(names, "vendor_ramdisk_table", "bootconfig")
		sizes = append(sizes, int64(le.Uint32(data[2112:])), int64(le.Uint32(data[2124:])))
	}
	if err := image.layout(data, page, 0, names, sizes); err != nil {
		return nil, err
	}
	if image.HeaderVersion < 4 {
		return image, nil
	}
	ramdisks, _ := image.Section("vendor_ramdisk")
	table, _ := image.Section("vendor_ramdisk_table")
	if entrySize < 108 || int64(tableEntries)*int64(entrySize) > table.Size {
		return nil, fmt.Errorf("vendor ramdisk table of %d bytes cannot hold %d entries of %d bytes", table.Size, tableEntries, entrySize)
	}
	for index := range int64(tableEntries) {
		raw := data[table.Offset+index*int64(entrySize):]
		entry := VendorRamdisk{Size: int64(le.Uint32(raw)), Offset: ramdisks.Offset + int64(le.Uint32(raw[4:])), Name: cString(raw[12:44]), BoardID: make([]uint32, 16)}
		kind := le.Uint32(raw[8:])
		entry.Type = fmt.Sprintf("unknown(%d)", kind)
		if int(kind) < len(ramdiskTypes) {
			entry.Type = ramdiskTypes[kind]
		}
		for word := range entry.BoardID {
			entry.BoardID[word] = le.Uint32(raw[44+4*word:])
		}
		if entry.Offset+entry.Size > ramdisks.Offset+ramdisks.Size {
			return nil, fmt.Errorf("vendor ramdisk %q lies outside the vendor ramdisk section", entry.Name)
		}
		image.VendorRamdisks = append(image.VendorRamdisks, entry)
	}
	if bootconfig, ok := image.Section("bootconfig"); ok {
		image.Bootconfig = string(data[bootconfig.Offset : bootconfig.Offset+bootconfig.Size])
	}
	return image, nil
}

// computeID repeats mkbootimg's v0-v2 id: the digest of each section followed by its little-endian size.
func (image *Image) computeID(data []byte, create func() hash.Hash) []byte {
	sum := create()
	for _, name := range []string{"kernel", "ramdisk", "second", "recovery_dtbo", "dtb"} {
		section, ok := image.Section(name)
		if !ok {
			continue
		}
		sum.Write(data[section.Offset : section.Offset+section.Size])
		sum.Write(binary.LittleEndian.AppendUint32(nil, uint32(section.Size)))
	}
	id := make([]byte, idSize)
	copy(id, sum.Sum(nil))
	return id
}

// IDAlgorithm reports which digest the stored v0-v2 id was built with, or "" when it is not a section digest.
func (image *Image) IDAlgorithm(data []byte) string {
	if image.Vendor || image.HeaderVersion >= 3 {
		return ""
	}
	stored := data[idOffset : idOffset+idSize]
	switch {
	case bytes.Equal(stored, image.computeID(data, sha1.New)):
		return "sha1"
	case bytes.Equal(stored, image.computeID(data, sha256.New)):
		return "sha256"
	}
	return ""
}

// UpdateID rewrites the v0-v2 id in data with the given algorithm after sections changed.
func (image *Image) UpdateID(data []byte, algorithm string) {
	switch algorithm {
	case "sha1":
		copy(data[idOffset:], image.computeID(data, sha1.New))
	case "sha256":
		copy(data[idOffset:], image.computeID(data, sha256.New))
	}
}
