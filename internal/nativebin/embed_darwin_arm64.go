//go:build nativeembed

package nativebin

import (
	"embed"
	"io/fs"
)

// The file suffix limits this to darwin/arm64, whose bundle embeds only the tools CMake staged in files/darwin_arm64.

//go:embed files/darwin_arm64/*
var embedded embed.FS

func embeddedFS() (fs.FS, error) { return fs.Sub(embedded, "files/darwin_arm64") }
