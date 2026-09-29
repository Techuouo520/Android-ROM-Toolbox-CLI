package cli

import (
	"fmt"
	"io"
	"path/filepath"

	"artb/internal/avb"
)

// checkVBMeta compares the hash descriptor in the footer of image with the one vbmetaPath records for the same partition.
func checkVBMeta(out, warn io.Writer, vbmetaPath, image string) error {
	if vbmetaPath == "" {
		return nil
	}
	vbmetaPath, err := filepath.Abs(vbmetaPath)
	if err != nil {
		return err
	}
	footer, err := avb.Read(image)
	if err != nil || footer.Footer == nil {
		_, err = fmt.Fprintf(warn, "%s has no AVB footer, so %s cannot be checked against it\n", image, vbmetaPath)
		return err
	}
	var own *avb.Descriptor
	for index := range footer.Descriptors {
		if footer.Descriptors[index].Kind == "hash" {
			own = &footer.Descriptors[index]
		}
	}
	if own == nil {
		_, err = fmt.Fprintf(warn, "%s footer has no hash descriptor to compare with %s\n", image, vbmetaPath)
		return err
	}
	meta, err := avb.Read(vbmetaPath)
	if err != nil {
		return err
	}
	for _, descriptor := range meta.Descriptors {
		if descriptor.Kind != "hash" || descriptor.Partition != own.Partition {
			continue
		}
		if descriptor.Digest == own.Digest && descriptor.ImageSize == own.ImageSize && descriptor.Salt == own.Salt {
			_, err = fmt.Fprintf(out, "vbmeta %s matches %s digest=%s\n", filepath.Base(vbmetaPath), own.Partition, own.Digest)
			return err
		}
		_, err = fmt.Fprintf(warn, "%s records %s image_size=%d digest=%s, but %s has image_size=%d digest=%s; run artb vbmeta sync %s %s\n", vbmetaPath, own.Partition, descriptor.ImageSize, descriptor.Digest, image, own.ImageSize, own.Digest, vbmetaPath, image)
		return err
	}
	for _, descriptor := range meta.Descriptors {
		if descriptor.Kind == "chain" && descriptor.Partition == own.Partition {
			_, err = fmt.Fprintf(out, "vbmeta %s chains %s to its own footer, which is not compared\n", filepath.Base(vbmetaPath), own.Partition)
			return err
		}
	}
	_, err = fmt.Fprintf(warn, "%s has no hash descriptor for %s\n", vbmetaPath, own.Partition)
	return err
}
