package avb

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/bits"
	"os"
	"sync"
	"sync/atomic"
)

const (
	footerVersionMajor = 1
	footerVersionMinor = 0
	hashtreeFixedSize  = 164
	hashFixedSize      = 116
)

func newHash(algorithm string) (func() hash.Hash, error) {
	switch algorithm {
	case "sha1":
		return sha1.New, nil
	case "sha256":
		return sha256.New, nil
	case "sha512":
		return sha512.New, nil
	}
	return nil, fmt.Errorf("unsupported hashtree algorithm %q", algorithm)
}

// hashtreeLevels returns avbtool's level sizes from level 0 upwards and the total tree size.
func hashtreeLevels(imageSize, blockSize, stride int64) ([]int64, int64) {
	var sizes []int64
	var total int64
	for size := imageSize; size > blockSize; {
		blocks := (size + blockSize - 1) / blockSize
		size = (blocks*stride + blockSize - 1) / blockSize * blockSize
		sizes = append(sizes, size)
		total += size
	}
	return sizes, total
}

// generateHashtree builds the dm-verity tree of the first imageSize bytes of input exactly as avbtool does: every
// block is hashed with the salt prepended, each level is padded to a block, and levels are stored top level first.
func generateHashtree(input io.ReaderAt, imageSize int64, blockSize int, algorithm string, salt []byte, workers int) ([]byte, []byte, error) {
	create, err := newHash(algorithm)
	if err != nil {
		return nil, nil, err
	}
	digestSize := create().Size()
	stride := int64(1) << bits.Len(uint(digestSize-1))
	block := int64(blockSize)
	if imageSize <= 0 || imageSize%block != 0 {
		return nil, nil, fmt.Errorf("hashtree input size %d is not a multiple of %d", imageSize, blockSize)
	}
	sizes, total := hashtreeLevels(imageSize, block, stride)
	if len(sizes) == 0 {
		data := make([]byte, block)
		if _, err = input.ReadAt(data, 0); err != nil && err != io.EOF {
			return nil, nil, err
		}
		digest := create()
		digest.Write(salt)
		digest.Write(data)
		return digest.Sum(nil), nil, nil
	}
	levels := make([][]byte, len(sizes))
	levels[0] = make([]byte, sizes[0])
	const chunkBlocks = 256
	blocks := imageSize / block
	chunks := (blocks + chunkBlocks - 1) / chunkBlocks
	var next atomic.Int64
	var failure atomic.Value
	var group sync.WaitGroup
	for range max(1, min(int64(workers), chunks)) {
		group.Add(1)
		go func() {
			defer group.Done()
			buffer := make([]byte, chunkBlocks*block)
			digest := create()
			for chunk := next.Add(1) - 1; chunk < chunks && failure.Load() == nil; chunk = next.Add(1) - 1 {
				first := chunk * chunkBlocks
				count := min(chunkBlocks, blocks-first)
				data := buffer[:count*block]
				if read, err := input.ReadAt(data, first*block); err != nil && !(err == io.EOF && read == len(data)) {
					failure.Store(fmt.Errorf("read hashtree input: %w", err))
					return
				}
				for index := range count {
					digest.Reset()
					digest.Write(salt)
					digest.Write(data[index*block : (index+1)*block])
					digest.Sum(levels[0][(first+index)*stride : (first+index)*stride : (first+index)*stride+stride])
				}
			}
		}()
	}
	group.Wait()
	if err, ok := failure.Load().(error); ok {
		return nil, nil, err
	}
	digest := create()
	for level := 1; level < len(sizes); level++ {
		levels[level] = make([]byte, sizes[level])
		source := levels[level-1]
		for index := int64(0); index*block < int64(len(source)); index++ {
			digest.Reset()
			digest.Write(salt)
			digest.Write(source[index*block : (index+1)*block])
			digest.Sum(levels[level][index*stride : index*stride : index*stride+stride])
		}
	}
	tree := make([]byte, 0, total)
	for level := len(levels) - 1; level >= 0; level-- {
		tree = append(tree, levels[level]...)
	}
	digest.Reset()
	digest.Write(salt)
	digest.Write(levels[len(levels)-1])
	return digest.Sum(nil), tree, nil
}

// span locates one descriptor inside a vbmeta blob.
type span struct {
	tag        uint64
	start, end int
}

func descriptorSpans(blob []byte) ([]span, error) {
	if _, err := Parse(blob); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	aux := HeaderSize + int(be.Uint64(blob[12:]))
	start, end := aux+int(be.Uint64(blob[96:])), aux+int(be.Uint64(blob[96:]))+int(be.Uint64(blob[104:]))
	var spans []span
	for position := start; position < end; {
		size := 16 + int(be.Uint64(blob[position+8:]))
		spans = append(spans, span{tag: be.Uint64(blob[position:]), start: position, end: position + size})
		position += size
	}
	return spans, nil
}

// descriptorPartition returns the partition name of a hashtree or hash descriptor.
func descriptorPartition(raw []byte, tag uint64) string {
	be := binary.BigEndian
	switch tag {
	case 1:
		return string(raw[16+hashtreeFixedSize : 16+hashtreeFixedSize+int(be.Uint32(raw[16+88:]))])
	case 2:
		return string(raw[16+hashFixedSize : 16+hashFixedSize+int(be.Uint32(raw[16+40:]))])
	}
	return ""
}

// rehash refreshes the vbmeta hash after the header or auxiliary block changed; the old signature is kept and no longer matches.
func rehash(blob []byte) bool {
	be := binary.BigEndian
	auth := blob[HeaderSize : HeaderSize+int(be.Uint64(blob[12:]))]
	digest := vbmetaDigest(be.Uint32(blob[28:]), blob[:HeaderSize], blob[HeaderSize+len(auth):])
	if digest == nil {
		return false
	}
	offset, size := be.Uint64(blob[32:]), be.Uint64(blob[40:])
	copy(auth[offset:offset+size], digest)
	return true
}

// FooterResult describes the AVB footer written to a partition image; StaleSignature means a signed footer vbmeta
// kept its old signature because no key was given.
type FooterResult struct {
	Size           int64
	Partition      string
	Descriptor     []byte
	StaleSignature bool
}

// finishBlob signs a signed vbmeta blob with key when one is given and otherwise only refreshes its hash.
func finishBlob(blob []byte, key *rsa.PrivateKey) ([]byte, bool, error) {
	if key != nil && binary.BigEndian.Uint32(blob[28:]) != 0 {
		signed, err := Sign(blob, key, nil)
		return signed, false, err
	}
	return blob, rehash(blob), nil
}

// AddHashtreeFooter appends a dm-verity hashtree, FEC parity, the vbmeta blob and the AVB footer to the filesystem
// image at path, taking the salt and parameters from the hashtree descriptor of template (the partition's previous
// footer vbmeta). The image keeps partitionSize when everything fits and otherwise grows to the minimum size.
func AddHashtreeFooter(path string, template []byte, partitionSize int64, key *rsa.PrivateKey, workers int) (*FooterResult, error) {
	blob := bytes.Clone(template)
	spans, err := descriptorSpans(blob)
	if err != nil {
		return nil, fmt.Errorf("footer vbmeta template: %w", err)
	}
	var found *span
	for index := range spans {
		if spans[index].tag == 1 {
			if found != nil {
				return nil, errors.New("footer vbmeta template has more than one hashtree descriptor")
			}
			found = &spans[index]
		}
	}
	if found == nil {
		return nil, errors.New("footer vbmeta template has no hashtree descriptor")
	}
	be := binary.BigEndian
	raw := blob[found.start:found.end]
	body := raw[16:]
	dataBlock, hashBlock, roots := be.Uint32(body[28:]), be.Uint32(body[32:]), be.Uint32(body[36:])
	if dataBlock != hashBlock || dataBlock == 0 || dataBlock%512 != 0 {
		return nil, fmt.Errorf("unsupported hashtree block sizes %d/%d", dataBlock, hashBlock)
	}
	nameSize, saltSize, digestSize := be.Uint32(body[88:]), be.Uint32(body[92:]), be.Uint32(body[96:])
	salt := body[hashtreeFixedSize+nameSize : hashtreeFixedSize+nameSize+saltSize]
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	block := int64(dataBlock)
	original := info.Size()
	imageSize := (original + block - 1) / block * block
	if err = file.Truncate(imageSize); err != nil {
		return nil, fmt.Errorf("pad image to block size: %w", err)
	}
	root, tree, err := generateHashtree(file, imageSize, int(dataBlock), cString(body[56:88]), salt, workers)
	if err != nil {
		return nil, err
	}
	if uint32(len(root)) != digestSize {
		return nil, fmt.Errorf("hashtree digest is %d bytes, descriptor expects %d", len(root), digestSize)
	}
	if _, err = file.WriteAt(tree, imageSize); err != nil {
		return nil, fmt.Errorf("write hashtree: %w", err)
	}
	fecOffset, fecSize := imageSize+int64(len(tree)), int64(0)
	if roots > 0 {
		parity, err := encodeFEC(file, fecOffset, int(roots), workers)
		if err != nil {
			return nil, err
		}
		if _, err = file.WriteAt(parity, fecOffset); err != nil {
			return nil, fmt.Errorf("write FEC: %w", err)
		}
		fecSize = int64(len(parity))
	}
	be.PutUint64(body[4:], uint64(imageSize))
	be.PutUint64(body[12:], uint64(imageSize))
	be.PutUint64(body[20:], uint64(len(tree)))
	be.PutUint64(body[40:], 0)
	if roots > 0 {
		be.PutUint64(body[40:], uint64(fecOffset))
	}
	be.PutUint64(body[48:], uint64(fecSize))
	copy(body[hashtreeFixedSize+nameSize+saltSize:], root)
	descriptor := bytes.Clone(raw)
	blob, stale, err := finishBlob(blob, key)
	if err != nil {
		return nil, err
	}
	size, err := writeFooterTail(file, blob, original, fecOffset+fecSize, partitionSize, block)
	if err != nil {
		return nil, err
	}
	if err = file.Close(); err != nil {
		return nil, err
	}
	return &FooterResult{Size: size, Partition: descriptorPartition(descriptor, 1), Descriptor: descriptor, StaleSignature: stale}, nil
}

// writeFooterTail stores the vbmeta blob at vbmetaOffset, zero-fills up to the partition size (or the minimum that fits)
// and ends the image with the AVB footer, as avbtool does for raw images.
func writeFooterTail(file *os.File, blob []byte, original, vbmetaOffset, partitionSize, block int64) (int64, error) {
	size := max(partitionSize, vbmetaOffset+(int64(len(blob))+block-1)/block*block+block)
	if size%block != 0 {
		return 0, fmt.Errorf("partition size %d is not a multiple of %d", size, block)
	}
	if _, err := file.WriteAt(blob, vbmetaOffset); err != nil {
		return 0, fmt.Errorf("write footer vbmeta: %w", err)
	}
	if err := file.Truncate(size); err != nil {
		return 0, fmt.Errorf("size image: %w", err)
	}
	be := binary.BigEndian
	footer := make([]byte, FooterSize)
	copy(footer, "AVBf")
	be.PutUint32(footer[4:], footerVersionMajor)
	be.PutUint32(footer[8:], footerVersionMinor)
	be.PutUint64(footer[12:], uint64(original))
	be.PutUint64(footer[20:], uint64(vbmetaOffset))
	be.PutUint64(footer[28:], uint64(len(blob)))
	if _, err := file.WriteAt(footer, size-FooterSize); err != nil {
		return 0, fmt.Errorf("write AVB footer: %w", err)
	}
	return size, nil
}

// AddHashFooter hashes the whole image at path (which has no footer yet) with the salt of the hash descriptor in
// template, then appends the vbmeta blob and footer like avbtool add_hash_footer, keeping partitionSize when it fits.
func AddHashFooter(path string, template []byte, partitionSize int64, key *rsa.PrivateKey) (*FooterResult, error) {
	blob := bytes.Clone(template)
	spans, err := descriptorSpans(blob)
	if err != nil {
		return nil, fmt.Errorf("footer vbmeta template: %w", err)
	}
	var found *span
	for index := range spans {
		if spans[index].tag == 2 {
			if found != nil {
				return nil, errors.New("footer vbmeta template has more than one hash descriptor")
			}
			found = &spans[index]
		}
	}
	if found == nil {
		return nil, errors.New("footer vbmeta template has no hash descriptor")
	}
	be := binary.BigEndian
	body := blob[found.start+16 : found.end]
	nameSize, saltSize, digestSize := be.Uint32(body[40:]), be.Uint32(body[44:]), be.Uint32(body[48:])
	create, err := newHash(cString(body[8:40]))
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	original := info.Size()
	digest := create()
	digest.Write(body[hashFixedSize+nameSize : hashFixedSize+nameSize+saltSize])
	if _, err = io.CopyBuffer(digest, io.NewSectionReader(file, 0, original), make([]byte, 1<<20)); err != nil {
		return nil, fmt.Errorf("hash %s: %w", path, err)
	}
	sum := digest.Sum(nil)
	if uint32(len(sum)) != digestSize {
		return nil, fmt.Errorf("digest is %d bytes, descriptor expects %d", len(sum), digestSize)
	}
	be.PutUint64(body[0:], uint64(original))
	copy(body[hashFixedSize+nameSize+saltSize:], sum)
	descriptor := bytes.Clone(blob[found.start:found.end])
	blob, stale, err := finishBlob(blob, key)
	if err != nil {
		return nil, err
	}
	const block = 4096
	size, err := writeFooterTail(file, blob, original, (original+block-1)/block*block, partitionSize, block)
	if err != nil {
		return nil, err
	}
	if err = file.Close(); err != nil {
		return nil, err
	}
	return &FooterResult{Size: size, Partition: descriptorPartition(descriptor, 2), Descriptor: descriptor, StaleSignature: stale}, nil
}

// UpdateHashFooter recomputes the hash descriptor of an image with an AVB hash footer, such as boot.img after a
// repack, over its first original_image_size bytes and signs or rehashes the footer vbmeta.
func UpdateHashFooter(path string, key *rsa.PrivateKey) (*FooterResult, error) {
	raw, err := ReadRaw(path)
	if err != nil {
		return nil, err
	}
	if raw.Footer == nil {
		return nil, fmt.Errorf("%s has no AVB footer", path)
	}
	spans, err := descriptorSpans(raw.Blob)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var found *span
	for index := range spans {
		if spans[index].tag == 2 {
			if found != nil {
				return nil, fmt.Errorf("%s: footer vbmeta has more than one hash descriptor", path)
			}
			found = &spans[index]
		}
	}
	if found == nil {
		return nil, fmt.Errorf("%s: footer vbmeta has no hash descriptor", path)
	}
	be := binary.BigEndian
	body := raw.Blob[found.start+16 : found.end]
	nameSize, saltSize, digestSize := be.Uint32(body[40:]), be.Uint32(body[44:]), be.Uint32(body[48:])
	create, err := newHash(cString(body[8:40]))
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	digest := create()
	digest.Write(body[hashFixedSize+nameSize : hashFixedSize+nameSize+saltSize])
	_, err = io.CopyBuffer(digest, io.NewSectionReader(file, 0, int64(raw.Footer.OriginalImageSize)), make([]byte, 1<<20))
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, fmt.Errorf("hash %s: %w", path, err)
	}
	sum := digest.Sum(nil)
	if uint32(len(sum)) != digestSize {
		return nil, fmt.Errorf("%s: digest is %d bytes, descriptor expects %d", path, len(sum), digestSize)
	}
	be.PutUint64(body[0:], raw.Footer.OriginalImageSize)
	copy(body[hashFixedSize+nameSize+saltSize:], sum)
	descriptor := bytes.Clone(raw.Blob[found.start:found.end])
	blob, stale, err := finishBlob(raw.Blob, key)
	if err != nil {
		return nil, err
	}
	if err = writeBlob(path, raw, blob); err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	return &FooterResult{Size: info.Size(), Partition: descriptorPartition(descriptor, 2), Descriptor: descriptor, StaleSignature: stale}, nil
}

// writeBlob stores a re-encoded vbmeta blob in place of raw, zeroing leftover bytes and updating the footer size field.
func writeBlob(path string, raw *Raw, blob []byte) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	end, oldEnd := raw.Offset+int64(len(blob)), raw.Offset+int64(len(raw.Blob))
	if raw.Footer != nil && end > info.Size()-FooterSize {
		return fmt.Errorf("%s: signed vbmeta of %d bytes does not fit before the AVB footer", path, len(blob))
	}
	if raw.Footer == nil && end > info.Size() {
		if err = file.Truncate(int64(roundUp(int(end), 4096))); err != nil {
			return err
		}
	}
	if _, err = file.WriteAt(blob, raw.Offset); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if oldEnd > end {
		if _, err = file.WriteAt(make([]byte, oldEnd-end), end); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	if raw.Footer != nil {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(blob)))
		if _, err = file.WriteAt(size[:], info.Size()-FooterSize+28); err != nil {
			return fmt.Errorf("write %s footer: %w", path, err)
		}
	}
	return file.Close()
}

// SignFile re-signs the vbmeta of a standalone vbmeta image or of a partition footer, writing to output when given.
func SignFile(path, output string, key *rsa.PrivateKey, chains map[string][]byte) error {
	target := path
	if output != "" && output != path {
		if err := copyFile(path, output); err != nil {
			return err
		}
		target = output
	}
	raw, err := ReadRaw(target)
	if err != nil {
		return err
	}
	blob, err := Sign(raw.Blob, key, chains)
	if err != nil {
		return fmt.Errorf("%s: %w", target, err)
	}
	return writeBlob(target, raw, blob)
}

// FooterDescriptors returns the hashtree and hash descriptors of a partition image footer keyed by partition name.
func FooterDescriptors(path string) (map[string][]byte, error) {
	raw, err := ReadRaw(path)
	if err != nil {
		return nil, err
	}
	if raw.Footer == nil {
		return nil, fmt.Errorf("%s has no AVB footer", path)
	}
	spans, err := descriptorSpans(raw.Blob)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	descriptors := map[string][]byte{}
	for _, item := range spans {
		if item.tag == 1 || item.tag == 2 {
			current := raw.Blob[item.start:item.end]
			descriptors[descriptorPartition(current, item.tag)] = bytes.Clone(current)
		}
	}
	return descriptors, nil
}

// Replacement reports which descriptors of a vbmeta image matched and which of them changed.
type Replacement struct {
	Matched        []string
	Updated        []string
	StaleSignature bool
}

// ReplaceDescriptors swaps hashtree and hash descriptors of the vbmeta image at path for the same-sized replacements
// keyed by partition name and refreshes the vbmeta hash; a signed image keeps its old, now mismatching signature.
func ReplaceDescriptors(path string, replacements map[string][]byte) (*Replacement, error) {
	raw, err := ReadRaw(path)
	if err != nil {
		return nil, err
	}
	spans, err := descriptorSpans(raw.Blob)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	result := &Replacement{}
	for _, item := range spans {
		current := raw.Blob[item.start:item.end]
		name := descriptorPartition(current, item.tag)
		replacement, ok := replacements[name]
		if !ok || (item.tag != 1 && item.tag != 2) || binary.BigEndian.Uint64(replacement) != item.tag {
			continue
		}
		if len(replacement) != len(current) {
			return nil, fmt.Errorf("%s: %s descriptor is %d bytes, replacement is %d", path, name, len(current), len(replacement))
		}
		result.Matched = append(result.Matched, name)
		if !bytes.Equal(current, replacement) {
			copy(current, replacement)
			result.Updated = append(result.Updated, name)
		}
	}
	if len(result.Updated) == 0 {
		return result, nil
	}
	result.StaleSignature = rehash(raw.Blob)
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	if _, err = file.WriteAt(raw.Blob, raw.Offset); err != nil {
		file.Close()
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return result, file.Close()
}

// VerifyFooter recomputes the hashtree and FEC, or the image hash, recorded in the AVB footer of a partition image and
// compares them with the stored data.
func VerifyFooter(path string, workers int) (*Descriptor, error) {
	raw, err := ReadRaw(path)
	if err != nil {
		return nil, err
	}
	if raw.Footer == nil {
		return nil, fmt.Errorf("%s has no AVB footer", path)
	}
	meta, err := Parse(raw.Blob)
	if err != nil {
		return nil, err
	}
	var descriptor *Descriptor
	for index := range meta.Descriptors {
		if kind := meta.Descriptors[index].Kind; kind == "hashtree" || kind == "hash" {
			descriptor = &meta.Descriptors[index]
		}
	}
	if descriptor == nil {
		return nil, fmt.Errorf("%s footer has no hashtree or hash descriptor", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	salt, err := hex.DecodeString(descriptor.Salt)
	if err != nil {
		return nil, err
	}
	digest, err := hex.DecodeString(descriptor.Digest)
	if err != nil {
		return nil, err
	}
	if descriptor.Kind == "hash" {
		create, err := newHash(descriptor.HashAlgorithm)
		if err != nil {
			return nil, err
		}
		sum := create()
		sum.Write(salt)
		if _, err = io.CopyBuffer(sum, io.NewSectionReader(file, 0, int64(descriptor.ImageSize)), make([]byte, 1<<20)); err != nil {
			return nil, err
		}
		if !bytes.Equal(sum.Sum(nil), digest) {
			return descriptor, fmt.Errorf("%s: image digest %x does not match descriptor %s", path, sum.Sum(nil), descriptor.Digest)
		}
		return descriptor, nil
	}
	root, tree, err := generateHashtree(file, int64(descriptor.ImageSize), int(descriptor.DataBlockSize), descriptor.HashAlgorithm, salt, workers)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(root, digest) {
		return descriptor, fmt.Errorf("%s: root digest %x does not match descriptor %s", path, root, descriptor.Digest)
	}
	stored := make([]byte, descriptor.TreeSize)
	if uint64(len(tree)) != descriptor.TreeSize || !readFull(file, stored, int64(descriptor.TreeOffset)) || !bytes.Equal(stored, tree) {
		return descriptor, fmt.Errorf("%s: stored hashtree differs from the recomputed tree", path)
	}
	if descriptor.FECRoots > 0 {
		parity, err := encodeFEC(file, int64(descriptor.TreeOffset+descriptor.TreeSize), int(descriptor.FECRoots), workers)
		if err != nil {
			return descriptor, err
		}
		stored = make([]byte, descriptor.FECSize)
		if uint64(len(parity)) != descriptor.FECSize || !readFull(file, stored, int64(descriptor.FECOffset)) || !bytes.Equal(stored, parity) {
			return descriptor, fmt.Errorf("%s: stored FEC differs from the recomputed parity", path)
		}
	}
	return descriptor, nil
}

func readFull(file *os.File, buffer []byte, offset int64) bool {
	count, err := file.ReadAt(buffer, offset)
	return count == len(buffer) && (err == nil || err == io.EOF)
}
