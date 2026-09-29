//go:build nativeembed && !android

package nativebin

import (
	"embed"
	"io/fs"
)

// GOOS=android also matches the _linux file suffix, so Android is excluded here and embeds files/android_arm64 instead.

//go:embed files/linux_arm64/*
var embedded embed.FS

func embeddedFS() (fs.FS, error) { return fs.Sub(embedded, "files/linux_arm64") }
