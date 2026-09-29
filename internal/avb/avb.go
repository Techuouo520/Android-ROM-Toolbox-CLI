// Package avb parses and patches Android Verified Boot 2.0 vbmeta structures.
package avb

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	HeaderSize               = 256
	FooterSize               = 64
	FlagHashtreeDisabled     = 1
	FlagVerificationDisabled = 2
	flagsOffset              = 120
	sparseMagic              = 0xed26ff3a
)

var algorithms = []string{"NONE", "SHA256_RSA2048", "SHA256_RSA4096", "SHA256_RSA8192", "SHA512_RSA2048", "SHA512_RSA4096", "SHA512_RSA8192"}

// Footer is the trailer that locates an embedded vbmeta blob at the end of a partition image.
type Footer struct {
	VersionMajor      uint32 `json:"version_major"`
	VersionMinor      uint32 `json:"version_minor"`
	OriginalImageSize uint64 `json:"original_image_size"`
	VBMetaOffset      uint64 `json:"vbmeta_offset"`
	VBMetaSize        uint64 `json:"vbmeta_size"`
}

// Descriptor holds the fields of any descriptor kind; unused fields stay empty.
type Descriptor struct {
	Kind                  string `json:"kind"`
	Tag                   uint64 `json:"tag"`
	Partition             string `json:"partition,omitempty"`
	ImageSize             uint64 `json:"image_size,omitempty"`
	HashAlgorithm         string `json:"hash_algorithm,omitempty"`
	Salt                  string `json:"salt,omitempty"`
	Digest                string `json:"digest,omitempty"`
	DMVerityVersion       uint32 `json:"dm_verity_version,omitempty"`
	TreeOffset            uint64 `json:"tree_offset,omitempty"`
	TreeSize              uint64 `json:"tree_size,omitempty"`
	DataBlockSize         uint32 `json:"data_block_size,omitempty"`
	HashBlockSize         uint32 `json:"hash_block_size,omitempty"`
	FECRoots              uint32 `json:"fec_num_roots,omitempty"`
	FECOffset             uint64 `json:"fec_offset,omitempty"`
	FECSize               uint64 `json:"fec_size,omitempty"`
	Flags                 uint32 `json:"flags,omitempty"`
	RollbackIndexLocation uint32 `json:"rollback_index_location,omitempty"`
	PublicKeySHA1         string `json:"public_key_sha1,omitempty"`
	Key                   string `json:"key,omitempty"`
	Value                 string `json:"value,omitempty"`
	Cmdline               string `json:"cmdline,omitempty"`
	publicKey             []byte
}

// PublicKey returns the raw AVB public key blob of a chain partition descriptor.
func (descriptor Descriptor) PublicKey() []byte { return bytes.Clone(descriptor.publicKey) }

// VBMeta is a parsed vbmeta blob and where it sits inside its file.
type VBMeta struct {
	Offset                int64        `json:"offset"`
	Footer                *Footer      `json:"footer,omitempty"`
	VersionMajor          uint32       `json:"required_libavb_version_major"`
	VersionMinor          uint32       `json:"required_libavb_version_minor"`
	Algorithm             string       `json:"algorithm"`
	RollbackIndex         uint64       `json:"rollback_index"`
	RollbackIndexLocation uint32       `json:"rollback_index_location"`
	Flags                 uint32       `json:"flags"`
	Release               string       `json:"release"`
	PublicKeySHA1         string       `json:"public_key_sha1,omitempty"`
	HashMatches           *bool        `json:"hash_matches,omitempty"`
	SignatureValid        *bool        `json:"signature_valid,omitempty"`
	Descriptors           []Descriptor `json:"descriptors"`
	publicKey             []byte
}

// PublicKey returns the raw AVB public key blob that signed this vbmeta.
func (meta *VBMeta) PublicKey() []byte { return bytes.Clone(meta.publicKey) }

// Raw is a vbmeta blob exactly as stored in its file.
type Raw struct {
	Blob   []byte
	Offset int64
	Footer *Footer
}

// ReadRaw returns the vbmeta blob of a standalone vbmeta image or of an image with an AVB footer.
func ReadRaw(path string) (*Raw, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	offset, limit, footer, err := locate(file, info.Size())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	header := make([]byte, HeaderSize)
	if _, err = file.ReadAt(header, offset); err != nil {
		return nil, fmt.Errorf("%s: read vbmeta header: %w", path, err)
	}
	total, err := blobSize(header, limit)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	blob := make([]byte, total)
	if _, err = file.ReadAt(blob, offset); err != nil {
		return nil, fmt.Errorf("%s: read vbmeta: %w", path, err)
	}
	return &Raw{Blob: blob, Offset: offset, Footer: footer}, nil
}

// Read locates and parses the vbmeta blob of a standalone vbmeta image or of an image with an AVB footer.
func Read(path string) (*VBMeta, error) {
	raw, err := ReadRaw(path)
	if err != nil {
		return nil, err
	}
	meta, err := Parse(raw.Blob)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	meta.Offset, meta.Footer = raw.Offset, raw.Footer
	return meta, nil
}

// locate returns the vbmeta offset, the bytes available for it and the footer when the blob is embedded.
func locate(file *os.File, size int64) (int64, int64, *Footer, error) {
	var head [4]byte
	if size >= 4 {
		if _, err := file.ReadAt(head[:], 0); err != nil {
			return 0, 0, nil, err
		}
	}
	if string(head[:]) == "AVB0" {
		return 0, size, nil, nil
	}
	if binary.LittleEndian.Uint32(head[:]) == sparseMagic {
		return 0, 0, nil, errors.New("Android sparse image: convert it with artb sparse to-raw first")
	}
	if size < FooterSize {
		return 0, 0, nil, errors.New("no AVB vbmeta header or footer found")
	}
	raw := make([]byte, FooterSize)
	if _, err := file.ReadAt(raw, size-FooterSize); err != nil {
		return 0, 0, nil, err
	}
	if string(raw[:4]) != "AVBf" {
		return 0, 0, nil, errors.New("no AVB vbmeta header or footer found")
	}
	be := binary.BigEndian
	footer := &Footer{VersionMajor: be.Uint32(raw[4:]), VersionMinor: be.Uint32(raw[8:]), OriginalImageSize: be.Uint64(raw[12:]), VBMetaOffset: be.Uint64(raw[20:]), VBMetaSize: be.Uint64(raw[28:])}
	end := uint64(size - FooterSize)
	if footer.VBMetaOffset > end || footer.VBMetaSize > end-footer.VBMetaOffset || footer.VBMetaSize < HeaderSize {
		return 0, 0, nil, fmt.Errorf("AVB footer points outside the image (offset %d size %d)", footer.VBMetaOffset, footer.VBMetaSize)
	}
	return int64(footer.VBMetaOffset), int64(footer.VBMetaSize), footer, nil
}

func blobSize(header []byte, limit int64) (int64, error) {
	if string(header[:4]) != "AVB0" {
		return 0, errors.New("bad vbmeta magic")
	}
	auth, aux := binary.BigEndian.Uint64(header[12:]), binary.BigEndian.Uint64(header[20:])
	if limit < HeaderSize || auth > uint64(limit-HeaderSize) || aux > uint64(limit-HeaderSize)-auth {
		return 0, fmt.Errorf("vbmeta blocks exceed the available %d bytes", limit)
	}
	return HeaderSize + int64(auth) + int64(aux), nil
}

// within reports whether [offset, offset+size) fits inside a block of the given length.
func within(offset, size, length uint64) bool { return offset <= length && size <= length-offset }

// Parse decodes a vbmeta blob that starts with the AVB0 header.
func Parse(blob []byte) (*VBMeta, error) {
	if len(blob) < HeaderSize {
		return nil, errors.New("vbmeta shorter than its header")
	}
	total, err := blobSize(blob, int64(len(blob)))
	if err != nil {
		return nil, err
	}
	be := binary.BigEndian
	field := func(offset int) uint64 { return be.Uint64(blob[offset:]) }
	authSize := field(12)
	auth, aux := blob[HeaderSize:HeaderSize+authSize], blob[HeaderSize+authSize:total]
	algorithm := be.Uint32(blob[28:])
	meta := &VBMeta{VersionMajor: be.Uint32(blob[4:]), VersionMinor: be.Uint32(blob[8:]), RollbackIndex: field(112), Flags: be.Uint32(blob[flagsOffset:]), RollbackIndexLocation: be.Uint32(blob[124:]), Release: strings.TrimRight(string(blob[128:176]), "\x00")}
	if int(algorithm) < len(algorithms) {
		meta.Algorithm = algorithms[algorithm]
	} else {
		meta.Algorithm = fmt.Sprintf("UNKNOWN_%d", algorithm)
	}
	hashOffset, hashSize, signatureOffset, signatureSize := field(32), field(40), field(48), field(56)
	keyOffset, keySize, keyMetaOffset, keyMetaSize, descriptorOffset, descriptorSize := field(64), field(72), field(80), field(88), field(96), field(104)
	if !within(hashOffset, hashSize, uint64(len(auth))) || !within(signatureOffset, signatureSize, uint64(len(auth))) {
		return nil, errors.New("vbmeta hash or signature lies outside the authentication block")
	}
	if !within(keyOffset, keySize, uint64(len(aux))) || !within(keyMetaOffset, keyMetaSize, uint64(len(aux))) || !within(descriptorOffset, descriptorSize, uint64(len(aux))) {
		return nil, errors.New("vbmeta public key or descriptors lie outside the auxiliary block")
	}
	if keySize > 0 {
		meta.publicKey = bytes.Clone(aux[keyOffset : keyOffset+keySize])
		meta.PublicKeySHA1 = sha1Hex(meta.publicKey)
	}
	if digest := vbmetaDigest(algorithm, blob[:HeaderSize], aux); digest != nil && hashSize > 0 {
		matches := bytes.Equal(digest, auth[hashOffset:hashOffset+hashSize])
		meta.HashMatches = &matches
		if keySize > 0 && signatureSize > 0 {
			valid := verifySignature(algorithm, digest, auth[signatureOffset:signatureOffset+signatureSize], meta.publicKey)
			meta.SignatureValid = &valid
		}
	}
	if meta.Descriptors, err = parseDescriptors(aux[descriptorOffset : descriptorOffset+descriptorSize]); err != nil {
		return nil, err
	}
	return meta, nil
}

// vbmetaDigest hashes the header and auxiliary block the way libavb does before checking the signature.
func vbmetaDigest(algorithm uint32, header, aux []byte) []byte {
	switch {
	case algorithm >= 1 && algorithm <= 3:
		sum := sha256.New()
		sum.Write(header)
		sum.Write(aux)
		return sum.Sum(nil)
	case algorithm >= 4 && algorithm <= 6:
		sum := sha512.New()
		sum.Write(header)
		sum.Write(aux)
		return sum.Sum(nil)
	}
	return nil
}

func sha1Hex(data []byte) string {
	sum := sha1.Sum(data)
	return hex.EncodeToString(sum[:])
}

func cString(data []byte) string {
	if index := bytes.IndexByte(data, 0); index >= 0 {
		return string(data[:index])
	}
	return string(data)
}

// tail splits the variable-length payload that follows a fixed descriptor body into the requested lengths.
func tail(body []byte, fixed int, lengths ...uint32) ([][]byte, error) {
	parts := make([][]byte, len(lengths))
	position := uint64(fixed)
	for index, length := range lengths {
		if !within(position, uint64(length), uint64(len(body))) {
			return nil, errors.New("descriptor payload exceeds its declared size")
		}
		parts[index] = body[position : position+uint64(length)]
		position += uint64(length)
	}
	return parts, nil
}

func parseDescriptors(data []byte) ([]Descriptor, error) {
	be := binary.BigEndian
	var descriptors []Descriptor
	for position := uint64(0); position < uint64(len(data)); {
		if uint64(len(data))-position < 16 {
			return nil, errors.New("truncated descriptor header")
		}
		tag, following := be.Uint64(data[position:]), be.Uint64(data[position+8:])
		if following%8 != 0 || following > uint64(len(data))-position-16 {
			return nil, fmt.Errorf("descriptor at %d has invalid size %d", position, following)
		}
		body := data[position+16 : position+16+following]
		position += 16 + following
		descriptor := Descriptor{Tag: tag}
		var parts [][]byte
		var err error
		switch tag {
		case 0:
			descriptor.Kind = "property"
			if len(body) < 16 {
				return nil, errors.New("truncated property descriptor")
			}
			keySize, valueSize := be.Uint64(body), be.Uint64(body[8:])
			if keySize > uint64(len(body)) || valueSize > uint64(len(body)) || !within(16, keySize+1+valueSize+1, uint64(len(body))) {
				return nil, errors.New("property descriptor payload exceeds its declared size")
			}
			descriptor.Key, descriptor.Value = string(body[16:16+keySize]), string(body[17+keySize:17+keySize+valueSize])
		case 1:
			descriptor.Kind = "hashtree"
			if len(body) < 164 {
				return nil, errors.New("truncated hashtree descriptor")
			}
			descriptor.DMVerityVersion, descriptor.ImageSize, descriptor.TreeOffset, descriptor.TreeSize = be.Uint32(body), be.Uint64(body[4:]), be.Uint64(body[12:]), be.Uint64(body[20:])
			descriptor.DataBlockSize, descriptor.HashBlockSize, descriptor.FECRoots, descriptor.FECOffset, descriptor.FECSize = be.Uint32(body[28:]), be.Uint32(body[32:]), be.Uint32(body[36:]), be.Uint64(body[40:]), be.Uint64(body[48:])
			descriptor.HashAlgorithm, descriptor.Flags = cString(body[56:88]), be.Uint32(body[100:])
			if parts, err = tail(body, 164, be.Uint32(body[88:]), be.Uint32(body[92:]), be.Uint32(body[96:])); err != nil {
				return nil, err
			}
			descriptor.Partition, descriptor.Salt, descriptor.Digest = string(parts[0]), hex.EncodeToString(parts[1]), hex.EncodeToString(parts[2])
		case 2:
			descriptor.Kind = "hash"
			if len(body) < 116 {
				return nil, errors.New("truncated hash descriptor")
			}
			descriptor.ImageSize, descriptor.HashAlgorithm, descriptor.Flags = be.Uint64(body), cString(body[8:40]), be.Uint32(body[52:])
			if parts, err = tail(body, 116, be.Uint32(body[40:]), be.Uint32(body[44:]), be.Uint32(body[48:])); err != nil {
				return nil, err
			}
			descriptor.Partition, descriptor.Salt, descriptor.Digest = string(parts[0]), hex.EncodeToString(parts[1]), hex.EncodeToString(parts[2])
		case 3:
			descriptor.Kind = "cmdline"
			if len(body) < 8 {
				return nil, errors.New("truncated kernel cmdline descriptor")
			}
			descriptor.Flags = be.Uint32(body)
			if parts, err = tail(body, 8, be.Uint32(body[4:])); err != nil {
				return nil, err
			}
			descriptor.Cmdline = string(parts[0])
		case 4:
			descriptor.Kind = "chain"
			if len(body) < 76 {
				return nil, errors.New("truncated chain partition descriptor")
			}
			descriptor.RollbackIndexLocation, descriptor.Flags = be.Uint32(body), be.Uint32(body[12:])
			if parts, err = tail(body, 76, be.Uint32(body[4:]), be.Uint32(body[8:])); err != nil {
				return nil, err
			}
			descriptor.Partition, descriptor.publicKey = string(parts[0]), bytes.Clone(parts[1])
			descriptor.PublicKeySHA1 = sha1Hex(parts[1])
		default:
			descriptor.Kind = "unknown"
		}
		descriptors = append(descriptors, descriptor)
	}
	return descriptors, nil
}

// SetFlags ORs set into and clears clear from the vbmeta flags of path, writing the result to output
// (path itself when output is empty), and returns the flags before and after.
func SetFlags(path, output string, set, clear uint32) (uint32, uint32, error) {
	meta, err := Read(path)
	if err != nil {
		return 0, 0, err
	}
	target := path
	if output != "" && output != path {
		if err = copyFile(path, output); err != nil {
			return 0, 0, err
		}
		target = output
	}
	updated := (meta.Flags | set) &^ clear
	if updated == meta.Flags && target == path {
		return meta.Flags, updated, nil
	}
	file, err := os.OpenFile(target, os.O_WRONLY, 0)
	if err != nil {
		return 0, 0, err
	}
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], updated)
	if _, err = file.WriteAt(raw[:], meta.Offset+flagsOffset); err != nil {
		file.Close()
		return 0, 0, fmt.Errorf("write vbmeta flags: %w", err)
	}
	if err = file.Close(); err != nil {
		return 0, 0, err
	}
	return meta.Flags, updated, nil
}

func copyFile(source, target string) (err error) {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(target)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := out.Close(); err == nil {
			err = closeErr
		}
	}()
	if _, err = io.CopyBuffer(out, in, make([]byte, 1<<20)); err != nil {
		return fmt.Errorf("copy %s: %w", source, err)
	}
	return nil
}
