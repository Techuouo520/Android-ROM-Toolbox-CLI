//go:build nativeembed

package nativebin

import (
	"embed"
	"io/fs"
)

// The file suffix limits this to windows/arm64, whose bundle embeds only the tools CMake staged in files/windows_arm64.

//go:embed files/windows_arm64/*
var embedded embed.FS

func embeddedFS() (fs.FS, error) { return fs.Sub(embedded, "files/windows_arm64") }
