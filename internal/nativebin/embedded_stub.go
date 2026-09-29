//go:build !nativeembed

package nativebin

import (
	"errors"
	"io/fs"
)

func embeddedFS() (fs.FS, error) {
	return nil, errors.New("native tools are not embedded in this build")
}
