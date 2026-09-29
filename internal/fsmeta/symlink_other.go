//go:build !windows

package fsmeta

import (
	"fmt"
	"io/fs"
	"os"
)

func symlinkTarget(path string, info fs.FileInfo) (string, bool, error) {
	if info.Mode()&fs.ModeSymlink == 0 {
		return "", false, nil
	}
	target, err := os.Readlink(path)
	if err != nil {
		return "", false, fmt.Errorf("read link %q: %w", path, err)
	}
	return target, true, nil
}
