//go:build windows

package fsmeta

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"unicode/utf16"
)

const cygwinMagic = "!<symlink>"

// symlinkTarget decodes the Cygwin placeholder files the extractors write for symlinks on Windows.
func symlinkTarget(path string, info fs.FileInfo) (string, bool, error) {
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok || data.FileAttributes&syscall.FILE_ATTRIBUTE_SYSTEM == 0 || !info.Mode().IsRegular() || info.Size() < int64(len(cygwinMagic)) || info.Size() > 65536 {
		return "", false, nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", false, fmt.Errorf("read %q: %w", path, err)
	}
	if !bytes.HasPrefix(content, []byte(cygwinMagic)) {
		return "", false, nil
	}
	body := content[len(cygwinMagic):]
	if len(body) >= 2 && body[0] == 0xff && body[1] == 0xfe {
		units := make([]uint16, 0, (len(body)-2)/2)
		for index := 2; index+1 < len(body); index += 2 {
			unit := uint16(body[index]) | uint16(body[index+1])<<8
			if unit == 0 {
				break
			}
			units = append(units, unit)
		}
		return string(utf16.Decode(units)), true, nil
	}
	if end := bytes.IndexByte(body, 0); end >= 0 {
		body = body[:end]
	}
	return string(body), true, nil
}
